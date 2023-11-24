#!/usr/bin/env python3
# coding: utf-8
# Copyright 2019-2023  Simon Arlott
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

from datetime import datetime, timedelta
from fractions import Fraction
from gnucash.gnucash_core_c import gnc_price_create, gnc_quote_source_get_internal_name, gnc_numeric_to_double
import argparse
import gnucash
import json
import locale
import logging
import logging.handlers
import pytz
import os
import shutil
import subprocess
import sys
import time
import traceback
import tzlocal
import urllib.parse
import urllib.request


locale.setlocale(locale.LC_ALL, "")

now = datetime.now().date()
#              M  T  W  T  F  S  S
check_days =  [3, 1, 1, 1, 1, 1, 2]

local_tz = tzlocal.get_localzone()


def _cty_id(cty):
	return "{0}/{1}".format(cty.get_namespace(), cty.get_mnemonic())


def _cty_desc(cty):
	return "{0}/{1} \"{2}\"".format(cty.get_namespace(), cty.get_mnemonic(), cty.get_fullname())


def read_prices(session):
	logging.debug("Reading prices")

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
				ts = price.get_time64().date()
				if key not in prices or ts > prices[key]:
					prices[key] = ts

		if cty.is_currency():
			for currency in currencies.values():
				if cty == currency or not currency.get_quote_flag():
					continue
				for price in pdb.get_prices(currency, cty)[0:1]:
					ts = price.get_time64().date()
					if key not in prices or ts > prices[key]:
						prices[key] = ts

	logging.debug("Read prices")
	return (commodities, currencies, prices)


def check_prices(offset, commodities, prices, late):
	logging.debug("Checking prices")

	if offset is None:
		offset = 0

	now_adjusted = now - timedelta(days=offset)
	logging.debug("Date offset = %d (%s)", offset, now_adjusted)

	ret = True
	for (key, value) in commodities.items():
		now_adjusted2 = now - timedelta(days=offset + late.get(_cty_id(value), 0))

		if key not in prices:
			logging.error("Missing any price data for %s", _cty_desc(value))
			ret = False
		elif now_adjusted2 - prices[key] > timedelta(days=check_days[now_adjusted2.weekday()]):
			logging.warning("Price data for %s not updated for %s (since %s)", _cty_desc(value), now_adjusted - prices[key], prices[key])
			ret = False

	logging.debug("Checked prices")
	return ret


def update_prices(session, base_currency, offset, all_commodities, currencies, prices, alphavantage_currency):
	logging.debug("Updating prices")

	ret = True
	update_commodities = {}

	if base_currency is None:
		root = session.book.get_root_account()
		base_currency = root.get_children_sorted()[0].GetCommodity().get_mnemonic()
	base_currency = currencies[base_currency]
	logging.debug("Base currency = %s", base_currency.get_mnemonic())

	if offset is None:
		offset = 0
	now_adjusted = now - timedelta(days=offset)
	while now_adjusted.isoweekday() in [6,7]:
		now_adjusted -= timedelta(days=1)
	logging.debug("Date offset = %d (%s)", offset, now_adjusted)

	for (key, commodity) in all_commodities.items():
		if commodity == base_currency:
			continue
		if key not in prices:
			logging.debug("Need to update %s (no prices)", _cty_desc(commodity))
			update_commodities[key] = commodity
		elif now_adjusted - prices[key] > timedelta(days=0):
			logging.debug("Need to update %s not updated for %s (since %s)", _cty_desc(commodity), now_adjusted - prices[key], prices[key])
			update_commodities[key] = commodity
		else:
			logging.debug("Price data for %s updated on %s", _cty_desc(commodity), prices[key])

	pdb = session.book.get_price_db()
	for (key, commodity) in update_commodities.items():
		logging.info("Updating %s", _cty_desc(commodity))
		try:
			result = quote_lookup(base_currency, commodity, alphavantage_currency)
		except Exception as e:
			logging.critical("Unable to get data for %s", _cty_desc(commodity))
			for line in traceback.format_exc().strip().split("\n"):
				logging.critical("%s", line)
			ret = False
			continue

		if result is None:
			logging.warning("No data for %s", _cty_desc(commodity))
		else:
			tz = commodity.get_quote_tz()
			if tz:
				result["ts"] = pytz.timezone(commodity.get_quote_tz()).localize(result["ts"])
			else:
				result["ts"] = local_tz.localize(result["ts"])

			if key in prices and result["ts"].date() <= prices[key]:
				logging.warning("Ignoring old data for %s", _cty_desc(commodity))
				result = None

		if result is not None:
			price = gnucash.GncPrice(instance=gnc_price_create(session.book.instance))
			price.set_commodity(commodity)
			price.set_currency(currencies[result["currency"]])
			price.set_source_string("Finance::Quote")
			price.set_typestr(result["type"])

			ts = datetime(result["ts"].year, result["ts"].month, result["ts"].day, 12, tzinfo=pytz.utc).astimezone(local_tz)
			price.set_time64(ts)

			value = Fraction.from_float(result["price"]).limit_denominator(1000000000)
			price.set_value(gnucash.GncNumeric(value.numerator, value.denominator))

			pdb.add_price(price)
			logging.info("Updated %s", _cty_desc(commodity))

	logging.debug("Updated prices")
	return ret


def quote_lookup(base_currency, commodity, alphavantage_currency):
	time.sleep(1)

	if commodity.is_currency() and alphavantage_currency:
		return quote_lookup_alphavantage_currency(base_currency, commodity)
	if shutil.which("finance-quote-wrapper"):
		return quote_lookup_gnucash5(base_currency, commodity)
	elif shutil.which("gnc-fq-helper"):
		return quote_lookup_gnucash4(base_currency, commodity)
	else:
		logging.error("GnuCash Finance::Quote helper not found")
		return None


def quote_lookup_gnucash4(base_currency, commodity):
	if commodity.is_currency():
		lookup = [b"currency", commodity.get_mnemonic(), base_currency.get_mnemonic()]
	else:
		lookup = [gnc_quote_source_get_internal_name(commodity.get_quote_source()).encode("utf-8"), commodity.get_mnemonic()]

	request = scheme_format(lookup)
	logging.debug("Lookup request: " + request)

	fq = subprocess.Popen(["gnc-fq-helper"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
	(response, stderr) = fq.communicate(request + "\n")

	logging.debug("Lookup response: %s", response.replace("\n", " "))
	if stderr:
		logging.error("Lookup error: %s", stderr)
	if fq.returncode:
		logging.error("Lookup return code: %d", fq.returncode)
	response = scheme_parse(response)

	if not response or not response[0] or response[0][0] != lookup[1]:
		return None

	data = {}
	for value in response[0][1:]:
		if len(value) != 2:
			continue

		if value[0] == "gnc:time-no-zone":
			data["ts"] = value[1]
		elif value[0] in [x for x in ["last", "nav", "price"]]:
			data["type"] = value[0]
			data["price"] = value[1]
		elif value[0] == "currency":
			data["currency"] = value[1]

	if "ts" in data and "type" in data and "price" in data and "currency" in data:
		return data
	return None


def scheme_parse(data):
	def _append_text(data):
		if data["text"] is not None:
			if data["symbol"]:
				if data["text"] == "#t":
					value = True
				elif data["text"] == "#f":
					value = False
				elif data["text"].startswith("#e"):
					value = float(data["text"][2:])
				else:
					try:
						value = float(data["text"])
					except ValueError:
						value = data["text"]
			else:
				try:
					value = datetime.strptime(data["text"], "%Y-%m-%d %H:%M:%S")
				except ValueError:
					value = data["text"]

			data["text"] = value
			data["values"].append(data["text"])
			data["text"] = None
		data["symbol"] = True

	def _pair_values(data):
		if len(data) == 3 and data[1] == ".":
			return (data[0], data[2])
		return data

	stack = [{"text": None, "symbol": True, "values": []}]
	in_str = False

	for c in data:
		if c == '"':
			if not in_str:
				stack[-1]["text"] = ""
				stack[-1]["symbol"] = False
			in_str = not in_str
		elif in_str:
			stack[-1]["text"] += c
		elif c == "(":
			stack.append({"text": None, "symbol": True, "values": []})
		elif c == ")":
			assert len(stack) > 1

			_append_text(stack[-1])

			if len(stack) == 2 and not stack[0]["values"]:
				return _pair_values(stack[1]["values"])
			else:
				stack[-2]["values"].append(_pair_values(stack[-1]["values"]))

			stack.pop()
		elif c == ' ' or c == '\r' or c == '\n':
			_append_text(stack[-1])
		else:
			if stack[-1]["text"] is None:
				stack[-1]["text"] = c
			else:
				stack[-1]["text"] += c

	if stack[0]["values"]:
		_append_text(stack[-1])

		return _pair_values(stack[0]["values"])
	else:
		return None


def scheme_format(data):
	assert(data is not None)
	if data is True:
		return "#t"
	elif data is False:
		return "#f"
	elif type(data) == list:
		return "(" + " ".join([format(x) for x in data]) + ")"
	elif type(data) == tuple:
		return "(" + " . ".join([format(x) for x in data]) + ")"
	elif type(data) == int:
		return str(data)
	elif type(data) == float:
		return "#e" + str(data)
	elif type(data) == str:
		return '"' + data + '"'
	elif type(data) == bytes:
		return data.decode("utf-8")
	else:
		assert False, type(data)


def quote_lookup_gnucash5(base_currency, commodity):
	time.sleep(1)

	lookup = { "defaultcurrency": base_currency.get_mnemonic() }

	if commodity.is_currency():
		lookup["currency"] = { commodity.get_mnemonic(): "" }
	else:
		lookup[gnc_quote_source_get_internal_name(commodity.get_quote_source())] = { commodity.get_mnemonic(): "" }

	request = json.dumps(lookup)
	logging.debug("Lookup request: " + request)

	fq = subprocess.Popen(["finance-quote-wrapper", "-f"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
	(response, stderr) = fq.communicate(request + "\n")

	logging.debug("Lookup response: %s", response.replace("\n", " "))
	if stderr:
		logging.error("Lookup error: %s", stderr)
	if fq.returncode:
		logging.error("Lookup return code: %d", fq.returncode)

	if not response:
		return None

	response = json.loads(response)

	if commodity.get_mnemonic() not in response:
		return None

	response = response[commodity.get_mnemonic()]
	if int(response.get("success", 0)) != 1:
		return None

	data = {}
	if "isodate" in response:
		if "time" not in response:
			response["time"] = "12:00:00"
		data["ts"] = datetime.fromisoformat(response["isodate"] + "T" + response["time"])
	else:
		data["ts"] = datetime.now()

	for x in ["last", "nav", "price"]:
		if x in response:
			data["type"] = x
			data["price"] = float(response[x])

	if commodity.is_currency() and int(response["inverted"]) == 1:
		data["price"] = 1 / float(data["price"])

	if "currency" in response:
		data["currency"] = response["currency"]

	if "ts" in data and "type" in data and "price" in data and "currency" in data:
		return data
	return None


def quote_lookup_alphavantage_currency(base_currency, commodity):
	request = {
		"function": "FX_DAILY",
		"from_symbol": commodity.get_mnemonic(),
		"to_symbol": base_currency.get_mnemonic(),
	}
	logging.debug(f"Alpha Vantage lookup request: {request!r}")
	request["apikey"] = os.environ["ALPHAVANTAGE_API_KEY"]
	url = "https://www.alphavantage.co/query?" + urllib.parse.urlencode(request)
	request = urllib.request.Request(
		url,
		data=None,
		headers={
			"User-Agent": "github.com/nomis/gnucash-prices/0",
		}
	)

	time.sleep(20)

	with urllib.request.urlopen(request) as conn:
		content = conn.read().decode("UTF-8")
		response = json.loads(content) if content else {}

		logging.debug("Alpha Vantage lookup response: status=%d len=%d err=%s refreshed=%s", conn.status, len(content),
			response.get("Error Message"), response.get("Meta Data", {}).get("5. Last Refreshed"))
		if conn.status != 200 or response.get("Error Message"):
			return None

	data = {}
	try:
		response = response["Time Series FX (Daily)"]
		day = sorted(response.keys(), reverse=True)[0]
		data["ts"] = datetime.fromisoformat(day + "T12:00")
		data["type"] = "last"
		data["price"] = float(response[day]["4. close"])
		data["currency"] = base_currency.get_mnemonic()
	except Exception:
		logging.exception(f"Alpha Vantage lookup response: {response!r}")
		raise

	logging.debug(f"Alpha Vantage lookup result: {data!r}")
	return data

def remove_user_currency_prices(session, currencies):
	pdb = session.book.get_price_db()

	for currency1 in currencies.values():
		for currency2 in currencies.values():
			if currency1 == currency2:
				continue
			for price in pdb.get_prices(currency1, currency2):
				if price.get_source_string().startswith("user:") and price.get_source_string() != "user:price-editor":
					logging.info("Remove price %s for CURRENCY %s/%s on %s (%s/%s)",
						gnc_numeric_to_double(price.get_value()),
						currency1.get_mnemonic(),
						currency2.get_mnemonic(),
						price.get_time64(),
						price.get_source_string(),
						price.get_typestr())
					pdb.remove_price(price)

def remove_user_commodity_prices(session, currencies):
	ctb = session.book.get_table()
	pdb = session.book.get_price_db()

	for ns in ctb.get_namespaces_list():
		for cty in ns.get_commodity_list():
			if cty.is_currency():
				continue
			for currency in currencies.values():
				for price in pdb.get_prices(cty, currency):
					if price.get_source_string().startswith("user:") and price.get_source_string() != "user:price-editor":
						logging.info("Remove price %s %s for %s on %s (%s/%s)",
							gnc_numeric_to_double(price.get_value()),
							currency.get_mnemonic(),
							_cty_desc(cty),
							price.get_time64(),
							price.get_source_string(),
							price.get_typestr())
						pdb.remove_price(price)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="GnuCash price database management")
	parser.add_argument("-f", "--file", dest="file", required=True, help="GnuCash file")
	parser.add_argument("-b", "--base", dest="currency", help="Base currency")
	parser.add_argument("-c", "--check", dest="check", action="store_true", help="Check that prices have been updated")
	parser.add_argument("-u", "--update", dest="update", action="store_true", help="Update prices that need to be updated")
	parser.add_argument("-o", "--offset", dest="offset", type=int, help="Date offset")
	parser.add_argument("-l", "--late", dest="late", nargs=2, default=[], action="append", type=str, metavar=("COMMODITY", "DAYS"), help="Date offset per commodity")
	parser.add_argument("--alphavantage-daily-currency", dest="alphavantage_currency", action="store_true", help="Use alphavantage daily values for currency lookups")
	parser.add_argument("--remove-user-currency-prices", dest="remove_user_currency", action="store_true", help="Remove user:* currency prices (except for user:price-editor)")
	parser.add_argument("--remove-user-commodity-prices", dest="remove_user_commodity", action="store_true", help="Remove user:* commodity prices (except for user:price-editor)")
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
			mode = gnucash.SessionOpenMode.SESSION_READ_ONLY
			if args.update or args.remove_user_currency or args.remove_user_commodity:
				mode = gnucash.SessionOpenMode.SESSION_NORMAL_OPEN
			before = datetime.today()
			session = gnucash.Session(args.file, mode=mode)
			after = datetime.today()
			logging.debug(f"File load time: {after - before}")
		except gnucash.gnucash_core.GnuCashBackendException as e:
			if gnucash.ERR_BACKEND_LOCKED not in e.errors:
				raise
			logging.debug("Backend locked")
			time.sleep(60)
			continue

		try:
			(commodities, currencies, prices) = read_prices(session)
			if args.remove_user_currency:
				remove_user_currency_prices(session, currencies)
			if args.remove_user_commodity:
				remove_user_commodity_prices(session, currencies)
			if args.update:
				ok = update_prices(session, args.currency, args.offset, commodities, currencies, prices, args.alphavantage_currency) and ok
			if args.check:
				ok = check_prices(args.offset, commodities, prices, {commodity: int(days) for commodity, days in args.late}) and ok
			if session.book.session_not_saved():
				logging.info("Saving changes")
				before = datetime.today()
				session.save()
				after = datetime.today()
				logging.debug(f"File save time: {after - before}")
		finally:
			session.end()
			session.destroy()

		break

	logging.debug("Finish")

	sys.exit(0 if ok else 1)
