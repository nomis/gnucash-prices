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
import argparse
import gnucash
import logging
import logging.handlers
import os
import sys
import time


now = datetime.now().date()
#       M  T  W  T  F  S  S
days = [3, 1, 1, 1, 1, 1, 2][now.weekday()]


def check_prices(session):
	ret = True

	commodities = {}
	prices = {}
	ctb = session.book.get_table()
	pdb = session.book.get_price_db()
	currencies = set()
	for ns in ctb.get_namespaces_list():
		for cty in ns.get_commodity_list():
			if cty.is_currency():
				if cty.get_mnemonic() in ["XXX"]:
					continue
				currencies.add(cty)
			if cty.get_quote_flag():
				commodities[(ns.get_name(), cty.get_mnemonic())] = cty

	for (key, cty) in commodities.items():
		for currency in currencies:
			if cty == currency:
				continue
			for price in pdb.get_prices(cty, currency)[0:1]:
				ts = price.get_time()
				if key not in prices or ts > prices[key]:
					prices[key] = ts

		if cty.is_currency():
			for currency in currencies:
				if cty == currency:
					continue
				for price in pdb.get_prices(currency, cty)[0:1]:
					ts = price.get_time()
					if key not in prices or ts > prices[key]:
						prices[key] = ts

	for (key, name) in commodities.items():
		if key not in prices:
			logging.error("Missing any price data for {0}/{1}".format(*key))
			ret = 1
		elif now - prices[key] > timedelta(days=days):
			logging.warning("Price data for {0}/{1} not updated for {2} (since {3})".format(*(key + (now - prices[key], prices[key]))))
			ret = 1

	return True


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Check GnuCash price database")
	parser.add_argument("-f", "--file", dest="file", required=True, help="GnuCash file")
	args = parser.parse_args()

	root = logging.getLogger()
	root.setLevel(level=logging.DEBUG)

	handler = logging.StreamHandler(sys.stdout)
	handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
	root.addHandler(handler)

	handler = logging.handlers.SysLogHandler("/dev/log")
	handler.setLevel(level=logging.INFO)
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
			ok = check_prices(session)
			if session.book.session_not_saved():
				logging.info("Saving changes")
				session.save()
		finally:
			session.end()
			session.destroy()

		break

	logging.debug("Finish")

	sys.exit(0 if ok else 1)

