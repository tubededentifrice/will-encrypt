#!/bin/bash
# Final demonstration of import-share feature

set -e

echo "========================================"
echo "Import Shares Feature Demonstration"
echo "========================================"
echo ""

# Clean up
rm -f demo*.yaml

# Create first vault
echo "1. Creating first vault (2-of-3)..."
printf "no\n" | python -m src.main init --k 2 --n 3 --vault demo1.yaml > demo1_out.txt 2>&1

SHARE1=$(grep -A 1 "Share 1/3:" demo1_out.txt | tail -1 | xargs)
SHARE2=$(grep -A 1 "Share 2/3:" demo1_out.txt | tail -1 | xargs)

echo "   ✓ Vault created: demo1.yaml"
echo ""
echo "   Extracted shares:"
echo "   Share 1: ${SHARE1:0:40}..."
echo "   Share 2: ${SHARE2:0:40}..."
echo ""

# Create second vault with imported shares
echo "2. Creating second vault with imported shares (same 2-of-3)..."
python -m src.main init --k 2 --n 3 --vault demo2.yaml \
  --import-share "$SHARE1" \
  --import-share "$SHARE2" > demo2_out.txt 2>&1

echo "   ✓ Vault created: demo2.yaml"
echo ""

# Show that it worked
if grep -q "RECONSTRUCTED FROM IMPORTED SHARES" demo2_out.txt; then
    echo "   ✓ Shares imported successfully"
else
    echo "   ✗ Share import failed"
    exit 1
fi

# Encrypt test messages
echo ""
echo "3. Encrypting test messages..."
python -m src.main encrypt --vault demo1.yaml --title "Test1" --message "Message in vault 1" > /dev/null 2>&1
python -m src.main encrypt --vault demo2.yaml --title "Test2" --message "Message in vault 2" > /dev/null 2>&1
echo "   ✓ Messages encrypted in both vaults"

# Decrypt both vaults with same shares
echo ""
echo "4. Decrypting both vaults with same shares..."
if python -m src.main decrypt --vault demo1.yaml --shares "$SHARE1" "$SHARE2" 2>&1 | grep -q "Message in vault 1"; then
    echo "   ✓ Demo1 decrypted successfully"
else
    echo "   ✗ Demo1 decryption failed"
    exit 1
fi

if python -m src.main decrypt --vault demo2.yaml --shares "$SHARE1" "$SHARE2" 2>&1 | grep -q "Message in vault 2"; then
    echo "   ✓ Demo2 decrypted successfully (same shares work!)"
else
    echo "   ✗ Demo2 decryption failed"
    exit 1
fi

echo ""
echo "5. Validating both vaults..."
python -m src.main validate --vault demo1.yaml > /dev/null 2>&1
python -m src.main validate --vault demo2.yaml > /dev/null 2>&1
echo "   ✓ Both vaults validated successfully"

# Clean up
rm -f demo*.yaml demo*_out.txt

echo ""
echo "========================================"
echo "✓ Demonstration complete!"
echo ""
echo "Key points demonstrated:"
echo "  • Created vault1 with 2-of-3 threshold"
echo "  • Imported shares into vault2"
echo "  • Both vaults use same passphrase"
echo "  • Same shares decrypt both vaults"
echo "  • All vaults validated successfully"
echo "========================================"
