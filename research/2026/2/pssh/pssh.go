package main

import "fmt"

func PowerSetRecursive(set []string) [][]string {
   // Base case: the power set of an empty set is a set containing the empty set.
   if len(set) == 0 {
      return [][]string{{}}
   }
   first := set[0]
   rest := set[1:]
   // Recursively find the power set of the rest of the elements.
   subPowerSet := PowerSetRecursive(rest)
   // Create a new slice to hold the subsets that include 'first'.
   // Pre-allocate with the same capacity as subPowerSet.
   newSubsets := make([][]string, 0, len(subPowerSet))
   for _, subset := range subPowerSet {
      // Create a new subset by adding 'first' to the existing one.
      newSubset := append([]string{first}, subset...)
      newSubsets = append(newSubsets, newSubset)
   }
   // The final power set is the combination of the two.
   return append(subPowerSet, newSubsets...)
}

func main() {
   items := []string{"a", "b", "c"}
   for _, subset := range PowerSetRecursive(items) {
      fmt.Println(subset)
   }
}
