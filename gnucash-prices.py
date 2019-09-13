#!/usr/bin/env python2
# coding: utf-8
# Copyright 2019  Simon Arlott
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function
from datetime import datetime, timedelta
from fractions import Fraction
from gnucash._gnucash_core_c import gnc_quote_source_get_internal_name
import argparse
import gnucash
import logging
import logging.handlers
import pytz
import os
import scheme
import subprocess
import sys
import time
import traceback
import tzlocal


now = datetime.now().date()
#       M  T  W  T  F  S  S
days = [3, 1, 1, 1, 1, 1, 2][now.weekday()]


def read_prices(session):
	logging.debug("Reading prices")
	ret = True

	commodities = {}
	prices = {}
	currencies = {}
	ctb = session.book.get_table()
	pdb = session.book.get_price_db()
	for ns in ctb.get_namespaces_list():
		for cty in ns.get_commodity_list():
			if cty.is_currency():
				if cty.get_mnemonic() in ["XXX"]:
					continue
				currencies[cty.get_mnemonic()] = cty
			if cty.get_quote_flag():
				commodities[(ns.get_name(), cty.get_mnemonic())] = cty

	for (key, cty) in commodities.items():
		for currency in currencies.values():
			if cty == currency or not currency.get_quote_flag():
				continue
			for price in pdb.get_prices(cty, currency)[0:1]:
				ts = price.get_time()
				if key not in prices or ts > prices[key]:
					prices[key] = ts

		if cty.is_currency():
			for currency in currencies.values():
				if cty == currency or not currency.get_quote_flag():
					continue
				for price in pdb.get_prices(currency, cty)[0:1]:
					ts = price.get_time()
					if key not in prices or ts > prices[key]:
						prices[key] = ts

	logging.debug("Read prices")
	return (commodities, currencies, prices)


def check_prices(commodities, prices):
	logging.debug("Checking prices")

	for (key, value) in commodities.items():
		if key not in prices:
			logging.error("Missing any price data for %s/%s", *key)
			ret = 1
		elif now - prices[key] > timedelta(days=days):
			logging.warning("Price data for %s/%s not updated for %s (since %s)", key[0], key[1], now - prices[key], prices[key])
			ret = 1

	logging.debug("Checked prices")
	return True


def update_prices(session, base_currency, offset, all_commodities, currencies, prices):
	logging.debug("Updating prices")

	update_commodities = {}

	if base_currency is None:
		root = session.book.get_root_account()
		base_currency = root.get_children_sorted()[0].GetCommodity().get_mnemonic()
	base_currency = currencies[base_currency]
	logging.debug("Base currency = %s", base_currency.get_mnemonic())

	if offset is None:
		offset = 0
	now_adjusted = now - timedelta(days=offset)
	logging.debug("Date offset = %d (%s)", offset, now_adjusted)

	for (key, commodity) in all_commodities.items():
		if commodity == base_currency:
			continue
		if key not in prices:
			logging.debug("Need to update %s/%s (no prices)", *key)
			update_commodities[key] = commodity
		elif now_adjusted - prices[key] > timedelta(days=days - 1):
			logging.debug("Need to update %s/%s not updated for %s (since %s)", key[0], key[1], now_adjusted - prices[key], prices[key])
			update_commodities[key] = commodity
		else:
			logging.debug("Price data for %s/%s updated on %s", key[0], key[1], prices[key])

	pdb = session.book.get_price_db()
	for (key, commodity) in update_commodities.items():
		if commodity.is_currency():
			lookup = ["currency", commodity.get_mnemonic().decode("utf-8"), base_currency.get_mnemonic().decode("utf-8")]
		else:
			lookup = [gnc_quote_source_get_internal_name(commodity.get_quote_source()), key[1].decode("utf-8")]
		logging.info("Updating %s/%s", key[0], key[1])
		try:
			result = quote_lookup(lookup)
		except KeyboardInterrupt:
			raise
		except Exception as e:
			logging.critical("Unable to get data for %s/%s")
			for line in traceback.format_exc().strip().split("\n"):
				logging.critical("%s", line)
			continue

		if result is None:
			logging.warn("No data for %s/%s", key[0], key[1])
		else:
			tz = commodity.get_quote_tz()
			if tz:
				result["ts"] = pytz.timezone(commodity.get_quote_tz()).localize(result["ts"])
			else:
				result["ts"] = tzlocal.get_localzone().localize(result["ts"])

		if result["ts"].date() <= prices[key]:
			logging.warn("Ignoring old data for %s/%s", key[0], key[1])
			result = None

		if result is not None:
			price = gnucash.GncPrice(instance=gnucash.gnucash_core_c.gnc_price_create(session.book.instance))
			price.set_commodity(commodity)
			price.set_currency(currencies[result["currency"]])
			price.set_source_string("Finance::Quote")
			price.set_typestr(result["type"])
			price.set_time(result["ts"])

			value = Fraction.from_float(result["price"]).limit_denominator(1000000000)
			price.set_value(gnucash.GncNumeric(value.numerator, value.denominator))

			pdb.add_price(price)
			logging.info("Updated %s/%s", key[0], key[1])

	logging.debug("Updated prices")
	return True


def quote_lookup(lookup):
	time.sleep(1)

	request = scheme.format(lookup)
	logging.debug("Lookup request: " + request)

	fq = subprocess.Popen(["gnc-fq-helper"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
	(response, stderr) = fq.communicate(request + "\n")

	logging.debug("Lookup response: %s", response.replace("\n", " "))
	if stderr:
		logging.error("Lookup error: %s", stderr)
	if fq.returncode:
		logging.error("Lookup return code: %d", fq.returncode)
	response = scheme.parse(response)

	if response is None or response[0] is None or response[0][0] != lookup[1]:
		return None

	data = {}
	for value in response[0][1:]:
		if len(value) != 2:
			continue

		if value[0] == "gnc:time-no-zone".decode("utf-8"):
			data["ts"] = value[1]
		elif value[0] in [x.decode("utf-8") for x in ["last", "nav", "price"]]:
			data["type"] = value[0].encode("utf-8")
			data["price"] = value[1]
		elif value[0] == "currency".decode("utf-8"):
			data["currency"] = value[1].encode("utf-8")

	if "ts" in data and "type" in data and "price" in data and "currency" in data:
		return data
	return None


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="GnuCash price database management")
	parser.add_argument("-f", "--file", dest="file", required=True, help="GnuCash file")
	parser.add_argument("-b", "--base", dest="currency", help="Base currency")
	parser.add_argument("-c", "--check", dest="check", action="store_true", help="Check that prices have been updated")
	parser.add_argument("-u", "--update", dest="update", action="store_true", help="Update prices that need to be updated")
	parser.add_argument("-o", "--offset", dest="offset", type=int, help="Date offset")
	args = parser.parse_args()

	root = logging.getLogger()
	root.setLevel(level=logging.DEBUG)

	handler = logging.StreamHandler(sys.stdout)
	handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
	root.addHandler(handler)

	handler = logging.handlers.SysLogHandler("/dev/log")
	handler.setLevel(level=logging.DEBUG)
	handler.setFormatter(logging.Formatter('gnucash-check-prices: %(levelname)s %(message)s'))
	root.addHandler(handler)

	ok = True

	logging.debug("Start")

	start = datetime.today()
	while datetime.today() - start < timedelta(hours=1):
		try:
			session = gnucash.Session(args.file, is_new=False)
		except gnucash.gnucash_core.GnuCashBackendException as e:
			if gnucash.ERR_BACKEND_LOCKED not in e.errors:
				raise
			logging.debug("Backend locked")
			time.sleep(60)
			continue

		try:
			(commodities, currencies, prices) = read_prices(session)
			if args.update:
				ok = update_prices(session, args.currency, args.offset, commodities, currencies, prices) and ok
			if args.check:
				ok = check_prices(commodities, prices) and ok
			if session.book.session_not_saved():
				logging.info("Saving changes")
				session.save()
		finally:
			session.end()
			session.destroy()

		break

	logging.debug("Finish")

	sys.exit(0 if ok else 1)

