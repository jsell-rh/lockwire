#!/usr/bin/env bash
while true; do
  claude --dangerously-skip-permissions --model opus[1m] "/develop"
done
