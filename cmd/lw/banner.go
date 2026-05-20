package main

import (
	"fmt"
	"io"
)

const fgCyberCyan = "\033[38;2;0;240;255m"
const fgAmber = "\033[38;2;255;176;0m"
const dim = "\033[2m"

func printWelcomeBanner(w io.Writer, code, link string) {
	fmt.Fprintf(w, "\r\n")
	fmt.Fprintf(w, "  %s┏╸%s%slockwire%s\r\n", dim, colorReset, fgCyberCyan, colorReset)
	fmt.Fprintf(w, "  %s┃%s\r\n", dim, colorReset)
	fmt.Fprintf(w, "  %s┃%s  code  %s%s%s\r\n", dim, colorReset, boldOn, code, colorReset)
	fmt.Fprintf(w, "  %s┃%s  link  %s%s%s\r\n", dim, colorReset, dim, link, colorReset)
	fmt.Fprintf(w, "  %s┗╸%s\r\n", dim, colorReset)
	fmt.Fprintf(w, "\r\n")
}
