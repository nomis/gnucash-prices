Description
===========

GnuCash price database management (alternative to ``--add-price-quotes``)

Usage
=====

Run the "check" process in the morning to check the previous day's prices exist::

	?	5	*	*	*	cronty .../gnucash-prices.py -c -f ...

Run the "update" process in the evening to get today's prices::

	?	18	*	*	*	cronty .../gnucash-prices.py -c -f ...
	?	21	*	*	*	cronty .../gnucash-prices.py -c -f ...

Run the "update" process overnight to get yesterday's prices::

	?	2	*	*	*	cronty .../gnucash-prices.py -u -o 1 -f ...
	?	4	*	*	*	cronty .../gnucash-prices.py -u -o 1 -f ...

You can set the base currency with ``-b XXX`` if the wrong one is detected.
