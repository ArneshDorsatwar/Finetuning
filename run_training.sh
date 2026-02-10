#!/bin/bash
# Run training in background - survives SSH disconnection

cd /home/adorsatwar/Finetuning/Finetuning
source venv/bin/activate

# Training with new script + pre-formatted data
nohup python scripts/train.py \
    --dataset data/processed/combined_train_formatted.json \
    --batch-size 2 \
    --grad-accum 4 \
    --epochs 3 \
    > training.log 2>&1 &

echo "Training started in background!"
echo "PID: $!"
echo ""
echo "Monitor with: tail -f training.log"
echo "Check GPU:    watch -n 1 nvidia-smi"
