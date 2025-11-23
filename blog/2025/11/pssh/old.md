## one step

we cant do it in one step, because CTV only has PSSH in the init file, and
Rakuten only has PSSH in the MPD

## two steps

1. MPD key ID
2. init key ID

the above fails because Rakuten needs content ID

1. MPD PSSH
2. init PSSH

the above works
