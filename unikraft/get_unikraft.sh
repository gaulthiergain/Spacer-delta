#!/bin/sh
git clone https://github.com/Krechals/unikraft/
cd unikraft
git checkout cde4c05f5528886f5d4b2cffbe45bb3e4ade4a62
git apply all_diff.diff