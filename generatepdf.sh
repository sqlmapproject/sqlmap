#!/bin/sh

pandoc -f markdown -o Users-manual.pdf --smart --normalize --tab-stop=4 --standalone --template=template.latex --toc --highlight-style=haddock --number-sections title.txt Users-manual.md
