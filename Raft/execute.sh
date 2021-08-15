#!/bin/sh

echo "Enter the number of nodes: "  
read noofnodes
echo "Enter the desired rate of the block creation (per second): "  
read blockrate
echo "Enter the desired rate of the transaction generation (per second): "  
read transactionrate

gnome-terminal -- /bin/sh -c "./beacon $noofnodes"

a=100
b=$((a+noofnodes))
while [ $a -lt $b ]
do 
    gnome-terminal -- /bin/sh -c "./bc $noofnodes $a $blockrate $transactionrate"
    a=$((a + 1))
done
