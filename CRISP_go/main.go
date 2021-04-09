package main

import (
	"fmt"
)

func main() {
	fmt.Println("Welcome to ZKB++")
	var input string
	fmt.Println("Which circuit do you want to run?")
	fmt.Println("Press 1 for crisp, 2 for dummy, 3 for sha")
	fmt.Println("Confirm your choice with Enter")
	fmt.Scanln(&input)
	if input == "crisp" || input == "1" || input == "" {
		fmt.Println("Running CRISP...")
		runCrisp()
	} else if input == "dummy" || input == "2" {
		fmt.Println("Running dummy circuit...")
		runDummyCircuit()
	} else if input == "sha" || input == "3" {
		fmt.Println("Running sha circuit...")
		runShaCircuit()
	} else {
		fmt.Println("Unkown command, Exiting...")
	}
}
