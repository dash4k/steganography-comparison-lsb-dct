# LSB vs. DCT Steganography Comparison

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://steganography-comparison-lsb-dct.streamlit.app)

An interactive Streamlit application for comparing **Least Significant Bit (LSB)** and **Discrete Cosine Transform (DCT)** image steganography. The app embeds text into an image, extracts it, applies simulated image attacks, and compares both techniques using common image-quality and error metrics.

## Features

- Encode and compare LSB and DCT methods side by side
- Decode hidden text from uploaded stego images
- Generate a full robustness report across multiple attack types
- Display MSE, PSNR, SSIM, and bit error rate (BER)
- Download stego images, altered images, difference maps, CSV reports, and image ZIP archives
- Visualize BER against attack strength

## Supported Attacks

- No attack
- JPEG compression
- Gaussian noise
- Gaussian blur
- Rotation
- Crop and resize

## How It Works

### LSB (Spatial Domain)

LSB steganography writes each secret message bit into the least significant bit of RGB channel values. It provides high capacity and often excellent image fidelity, but it is generally sensitive to compression and geometric edits.

### DCT (Frequency Domain)

DCT steganography processes the image in 8×8 blocks and embeds secret bits by changing the relationship between selected middle-frequency coefficients: `(4,3)` and `(3,4)`. This is typically more robust to some transformations than direct pixel-level LSB embedding, but it has less capacity.

Both methods append an eight-zero-bit terminator to mark the end of the secret text.

## Metrics

- **MSE**: Mean Squared Error; lower values indicate less distortion
- **PSNR**: Peak Signal-to-Noise Ratio; higher values indicate better quality
- **SSIM**: Structural Similarity Index; values closer to 1 indicate greater structural similarity
- **BER**: Bit Error Rate; the percentage of secret-message bits that differ after extraction

## Running Locally

### 1. Clone the repository

```bash
git clone https://github.com/dash4k/steganography-comparison-lsb-dct.git
cd steganography-comparison-lsb-dct
```

### 2. Create and activate a virtual environment

```bash
python -m venv venv
```

- Windows:

  ```bash
  venv\Scripts\activate
  ```

- macOS/Linux:

  ```bash
  source venv/bin/activate
  ```

### 3. Install dependencies

```bash
pip install -r requirements.txt
pip install scipy pandas
```

### 4. Start the app

```bash
streamlit run app.py
```

Open the local URL printed by Streamlit in your browser.

## Using the App

### Encode & Compare

1. Upload a PNG or BMP cover image.
2. Enter the secret text.
3. Select an attack type and strength.
4. Choose **Process & Compare Both Methods**.
5. Review the metrics and extracted messages, or download generated images.

### Decode Message

1. Upload a stego PNG or BMP image.
2. Select **LSB (Spatial)** or **DCT (Frequency)**.
3. Optionally apply an attack before extraction.
4. Choose **Extract Message**.

### Full Report

1. Upload a cover image and enter a secret message.
2. Select the number of steps and the attacks to include.
3. Choose whether to include attacked images in the ZIP archive.
4. Generate the report and export it as CSV or download the resulting images.

## Requirements

The project uses:

- Streamlit
- Pillow
- NumPy
- SciPy
- scikit-image
- pandas

Python 3.9 or newer is recommended.

## Notes

- Cover images are processed as RGB images.
- LSB embedding is limited by the number of RGB color channels and pixels.
- DCT embedding requires image dimensions compatible with 8×8 blocks and has lower capacity.
- PNG is recommended for lossless storage of stego images.
- Decoding works best when the image still contains the original embedded format and byte terminator.

## Repository Structure

```text
.
├── app.py            # Streamlit interface and steganography implementations
├── requirements.txt  # Application dependencies
├── .gitignore
└── README.md
```