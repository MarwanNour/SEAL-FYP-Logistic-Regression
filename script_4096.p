# Set the output terminal
set terminal canvas
set output "canvas_4096.html"
set title "CKKS Benchmark 4096"
set xlabel 'Input Vector Size'
set ylabel 'Time (microseconds)'
# Set the styling 
set style line 1\
linecolor rgb '#0060ad'\
linetype 1 linewidth 2\
pointtype 7 pointsize 1.5
set style line 2\
linecolor rgb '#dd181f'\
linetype 1 linewidth 2\
pointtype 5 pointsize 1.5
set style line 3\
linecolor rgb '#00FF00'\
linetype 1 linewidth 2\
pointtype 6 pointsize 1.5
set style line 4\
linecolor rgb '#EC00EC'\
linetype 1 linewidth 2\
pointtype 4 pointsize 1.5
plot 'bench_4096.dat' index 0 with linespoints ls 1, \
'' index 1 with linespoints ls 2, \
'' index 2 with linespoints ls 3, \
'' index 3 with linespoints ls 4