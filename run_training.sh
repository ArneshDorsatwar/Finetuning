#!/bin/bash
# Run training in background - survives SSH disconnection

cd /home/adorsatwar/Finetuning/Finetuning
source venv/bin/activate

# Training with all optimizations
nohup python scripts/train_local.py \
    --data-path v2/data/processed/training_data_final.json \
    --batch-size 4 \
    --gradient-accumulation 4 \
    --packing \
    --epochs 3 \
    --save-gguf \
    > training.log 2>&1 &

echo "Training started in background!"
echo "PID: $!"
echo ""
echo "Monitor with: tail -f training.log"
echo "Check GPU:    watch -n 1 nvidia-smi"
