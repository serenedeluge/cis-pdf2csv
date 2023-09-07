# cis-pdf2csv
python script for converting pdf CIS benchmarks to csv

The Centre for Internet Security publiches some superb, industry leading hardening guides for a wide range of technologies (https://www.cisecurity.org/cis-benchmarks). These guides tell how to configure the technologies so as to prevent the exploitation of common configuration errors. The benchmarks though are published in PDF format, which makes it difficult for reviewing and applying the controls. This python script takes those PDF guides and converts them to CSV format.

To use it, download and open a PDF benchmark. Copy all of the text out (Ctrl + A) and paste it into a text file. Save the text file as 'input.txt'. Then run pdf2csv.py.

Any ideas or suggestions on how to improve the code are very welcome.
