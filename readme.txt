#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

Requirements:
+ Python 2.7.12
+ lxml: check out http://lxml.de/

Usage:
+ DCBot: python dcbot.py -a ADDRESS [-d DEBUG] -p PORT [-n NICK] [-v]
+ Parsing: python manage.py --parse_filelists
+ Statistics: python manage.py --statistics
++ creates statistics.html

+ main: main.py -p -s
++ starts DCBot, parses filelists and creates statistics. Use data/hublist.txt as input.

Documentation
+ Sphinx: docs/sphinx/_build/html/index.html
+ Workout: Dokumentation.pdf
+ ER-Model: docs/er_model.pdf

Logs:
+ Log file: debug/debug.txt
