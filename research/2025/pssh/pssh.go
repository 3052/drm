package pssh

import "errors"

var Methods = []struct {
   one    string
   two    string
   three  string
   four   string
   result error
}{
   {
      one:    "MPD content ID",
      // https://ctv.ca MPD is missing PSSH but has default_KID
      two:    "MPD key ID",
      three:  "initialization content ID",
      result: nil,
   },
   {
      one:    "MPD content ID",
      result: errors.New("need key ID"),
   },
   {
      three:  "initialization content ID",
      result: errors.New("need key ID"),
   },
   {
      one: "MPD content ID",
      two: "MPD key ID",
      result: errors.New(`https://ctv.ca need content ID,
      and its only in the initialization`),
   },
   {
      four:   "initialization key ID",
      result: errors.New("https://ctv.ca need content ID"),
   },
   {
      one:    "MPD content ID",
      three:  "initialization content ID",
      result: errors.New("need key ID"),
   },
   {
      two:    "MPD key ID",
      four:   "initialization key ID",
      result: errors.New("https://ctv.ca need content ID"),
   },
   {
      two:   "MPD key ID",
      three: "initialization content ID",
      result: errors.New(`https://rakuten.tv need content ID,
      and its only in the MPD`),
   },
   {
      two:   "MPD key ID",
      three: "initialization content ID",
      four:  "initialization key ID",
      result: errors.New(`https://rakuten.tv need content ID,
      and its only in the MPD`),
   },
   {
      one:  "MPD content ID",
      four: "initialization key ID",
      result: errors.New(`https://ctv.ca need content ID,
      and its only in the initialization`),
   },
   {
      one:  "MPD content ID",
      two:  "MPD key ID",
      four: "initialization key ID",
      result: errors.New(`https://ctv.ca need content ID,
      and its only in the initialization`),
   },
   {
      two:    "MPD key ID",
      result: errors.New("https://ctv.ca need content ID"),
   },
   {
      three: "initialization content ID",
      four:  "initialization key ID",
      result: errors.New(`https://rakuten.tv need content ID,
      and its only in the MPD`),
   },
}
