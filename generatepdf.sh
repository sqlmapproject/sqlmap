#!/bin/sh

pandoc -f markdown -o README.pdf --smart --normalize --tab-stop=4 --standalone --template=template.latex --variable version=1.0-dev --variable author-meta="sqlmap developers" --variable title-meta="sqlmap user's manual" --no-wrap --toc --highlight-style=haddock --number-sections title.txt Scenario.md Techniques.md Features.md Download-and-update.md Dependencies.md History.md Usage.md License-and-copyright.md

pandoc -f markdown -o FAQ.pdf --smart --normalize --tab-stop=4 --standalone --template=template.latex --variable version=1.0-dev --variable author-meta="sqlmap developers" --variable title-meta="sqlmap frequently asked questions (FAQ)" --no-wrap --toc --highlight-style=haddock --number-sections title_faq.txt FAQ.md
