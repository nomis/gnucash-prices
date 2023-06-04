Description
===========

GnuCash price database management (alternative to ``--add-price-quotes``).

Update Prices
-------------

Incrementally retrieves prices for securities that don't have already have a
price for the current date. This can be adjusted with an offset so that it
only retries securities with outdated prices, which is useful for securities
that provide prices late or when price retrieval may have failed.

Check Prices
------------

Check that prices for all securities for the previous day exist, and report
those that don't have prices. This makes it possible to identify when one or
more lookups are failing.

Automatic Price Removal
-----------------------

GnuCash likes to automatically add ``user:*`` prices based on transaction
exchange rates. These can't be disabled and would prevent prices being retrieved
or stored for the same date. Use ``--remove-user-currency-prices`` and
``--remove-user-commodity-prices`` to automatically get rid of these.

Prices manually added (``user:price-editor``) will be not be removed.


Usage
=====

Run the "check" process in the morning to check the previous day's prices exist::

	?	5	*	*	*	cronty .../gnucash-prices.py -c -f ...

Run the "update" process in the evening to get today's prices::

	?	18	*	*	*	cronty .../gnucash-prices.py -u -f ...
	?	21	*	*	*	cronty .../gnucash-prices.py -u -f ...

Run the "update" process overnight to get yesterday's prices::

	?	2	*	*	*	cronty .../gnucash-prices.py -u -o 1 -f ...
	?	4	*	*	*	cronty .../gnucash-prices.py -u -o 1 -f ...

You can set the base currency with ``-b XXX`` if the wrong one is detected.
