package main

import "fmt"

func s1() {
	fmt.Println("Set 1")
	c1()
	c2()
	c3()
	c4()
	c5()
	c6()
	c7()
	c8()
	fmt.Println()
}

func s2() {
	fmt.Println("Set 2")
	c9()
	c10()
	c11()
}

func main() {
	s1()
	s2()
}
