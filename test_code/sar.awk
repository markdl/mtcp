{ u_sum += $4; s_sum += $6; } END { print u_sum / NR; print s_sum / NR; }
