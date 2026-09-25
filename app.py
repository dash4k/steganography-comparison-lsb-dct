import zipfile
import io
import scipy.fftpack
import numpy as np
import streamlit as st
from PIL import Image, ImageChops, ImageEnhance, ImageFilter
from skimage.metrics import structural_similarity as ssim
import csv

st.set_page_config(
    page_title="Steganography Comparison",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stApp { background-color: #0e1117; }
    .main-header {
        background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
        padding: 1.5rem 1rem;
        border-radius: 12px;
        border: 1px solid #374151;
        margin-bottom: 2rem;
    }
    .main-header h1 { color: #f9fafb; margin: 0; font-weight: 700; font-size: 2.2rem; }
    .main-header p { color: #9ca3af; margin-top: 0.5rem; margin-bottom: 0; font-size: 1rem; }
    .metric-card {
        background-color: #1f2937;
        border: 1px solid #374151;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover { border-color: #3b82f6; transform: translateY(-2px); }
    .metric-label { color: #9ca3af; font-size: 0.8rem; text-transform: uppercase; font-weight: 600; }
    .metric-value { color: #f3f4f6; font-size: 1.5rem; font-weight: 700; margin: 0.3rem 0; }
    .metric-status { font-size: 0.75rem; padding: 2px 8px; border-radius: 12px; display: inline-block; font-weight: 600; }
    .status-good { background-color: rgba(16, 185, 129, 0.2); color: #10b981; }
    .status-warn { background-color: rgba(245, 158, 11, 0.2); color: #f59e0b; }
</style>
""", unsafe_allow_html=True)


def text_to_bin(text: str) -> str:
    """Convert text to binary with an 8-zero byte terminator."""
    return ''.join(f"{ord(char):08b}" for char in text) + '00000000'

def bin_to_text(binary_str: str) -> str:
    """Convert binary sequence back to text."""
    bytes_data = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    text = []
    for byte in bytes_data:
        if byte == '00000000':
            break
        text.append(chr(int(byte, 2)))
    return "".join(text)

def image_to_bytes(img: Image.Image, format: str = "PNG") -> bytes:
    """Convert a PIL Image to raw bytes for Streamlit downloading."""
    buf = io.BytesIO()
    img.save(buf, format=format)
    return buf.getvalue()


def apply_attack(img: Image.Image, attack_type: str, strength: float) -> Image.Image:
    """Apply a chosen distortion to simulate real-world transmission/editing."""
    img = img.convert('RGB')

    if attack_type == "None":
        return img.copy()

    if attack_type == "JPEG Compression":
        quality = int(strength)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality)
        buf.seek(0)
        return Image.open(buf).convert('RGB')

    if attack_type == "Gaussian Noise":
        arr = np.array(img, dtype=np.float32)
        noise = np.random.normal(0, strength, arr.shape)
        arr = np.clip(arr + noise, 0, 255).astype(np.uint8)
        return Image.fromarray(arr)

    if attack_type == "Gaussian Blur":
        return img.filter(ImageFilter.GaussianBlur(radius=strength))

    if attack_type == "Rotation":
        return img.rotate(strength, resample=Image.BICUBIC, fillcolor=(0, 0, 0))

    if attack_type == "Crop & Resize":
        w, h = img.size
        crop_frac = max(0.05, min(strength / 100.0, 0.5))
        left, top = int(w * crop_frac / 2), int(h * crop_frac / 2)
        right, bottom = w - left, h - top
        cropped = img.crop((left, top, right, bottom))
        return cropped.resize((w, h), Image.BICUBIC)

    return img.copy()


class LSBSteganography:
    @classmethod
    def encode(cls, image: Image.Image, secret_text: str) -> Image.Image:
        img = image.convert('RGB')
        pixels = np.array(img, dtype=np.uint8)
        
        binary_secret = text_to_bin(secret_text)
        data_len = len(binary_secret)
        flat_pixels = pixels.flatten()
        
        if data_len > len(flat_pixels):
            raise ValueError(f"Message exceeds LSB capacity! ({data_len} bits needed, {len(flat_pixels)} available)")

        bits = np.array([int(b) for b in binary_secret], dtype=np.uint8)
        flat_pixels[:data_len] = (flat_pixels[:data_len] & 0xFE) | bits
        
        return Image.fromarray(flat_pixels.reshape(pixels.shape))

    @classmethod
    def decode(cls, image: Image.Image) -> str:
        img = image.convert('RGB')
        pixels = np.array(img, dtype=np.uint8)
        flat_pixels = pixels.flatten()
        
        lsb_bits = flat_pixels & 1
        binary_chunks = []
        for i in range(0, len(lsb_bits), 8):
            byte = "".join(map(str, lsb_bits[i:i+8]))
            if byte == '00000000':
                break
            binary_chunks.append(byte)
            
        return bin_to_text("".join(binary_chunks) + '00000000')


class DCTSteganography:
    """2D-DCT Steganography modifying middle-frequency coefficients (4,3) & (3,4) in 8x8 blocks."""
    
    @staticmethod
    def dct2(a):
        return scipy.fftpack.dct(scipy.fftpack.dct(a.T, norm='ortho').T, norm='ortho')

    @staticmethod
    def idct2(a):
        return scipy.fftpack.idct(scipy.fftpack.idct(a.T, norm='ortho').T, norm='ortho')

    @classmethod
    def encode(cls, image: Image.Image, secret_text: str) -> Image.Image:
        img = image.convert('RGB')
        img_arr = np.array(img, dtype=np.float32)
        
        binary_secret = text_to_bin(secret_text)
        data_len = len(binary_secret)
        
        h, w, c = img_arr.shape
        blocks_h, blocks_w = h // 8, w // 8
        max_capacity = blocks_h * blocks_w * c
        
        if data_len > max_capacity:
            raise ValueError(f"Message exceeds DCT capacity! ({data_len} bits needed, {max_capacity} available)")
        
        bit_idx = 0
        stego_arr = img_arr.copy()
        
        for channel in range(c):
            for i in range(blocks_h):
                for j in range(blocks_w):
                    if bit_idx >= data_len:
                        break
                    
                    r_start, c_start = i * 8, j * 8
                    block = stego_arr[r_start:r_start+8, c_start:c_start+8, channel]
                    
                    dct_block = cls.dct2(block)
                    bit = int(binary_secret[bit_idx])
                    
                    c1, c2 = dct_block[4, 3], dct_block[3, 4]
                    c1, c2 = dct_block[4, 3], dct_block[3, 4]
                    quant_diff = 70.0

                    if bit == 1:
                        dct_block[4, 3] = c2 + quant_diff
                        dct_block[3, 4] = c2
                    else:
                        dct_block[3, 4] = c1 + quant_diff
                        dct_block[4, 3] = c1
                            
                    stego_arr[r_start:r_start+8, c_start:c_start+8, channel] = cls.idct2(dct_block)
                    bit_idx += 1
                if bit_idx >= data_len:
                    break
            if bit_idx >= data_len:
                break
                
        stego_arr = np.clip(stego_arr, 0, 255).astype(np.uint8)
        return Image.fromarray(stego_arr)

    @classmethod
    def decode(cls, image: Image.Image) -> str:
        img = image.convert('RGB')
        img_arr = np.array(img, dtype=np.float32)
        h, w, c = img_arr.shape
        
        blocks_h, blocks_w = h // 8, w // 8
        binary_bits = []
        
        for channel in range(c):
            for i in range(blocks_h):
                for j in range(blocks_w):
                    r_start, c_start = i * 8, j * 8
                    block = img_arr[r_start:r_start+8, c_start:c_start+8, channel]
                    
                    dct_block = cls.dct2(block)
                    c1, c2 = dct_block[4, 3], dct_block[3, 4]
                    
                    binary_bits.append("1" if c1 > c2 else "0")
                    
                    if len(binary_bits) % 8 == 0 and len(binary_bits) >= 8:
                        last_byte = "".join(binary_bits[-8:])
                        if last_byte == "00000000":
                            return bin_to_text("".join(binary_bits))
                            
        return bin_to_text("".join(binary_bits))


def compute_metrics(orig_img: Image.Image, enc_img: Image.Image, orig_text: str, ext_text: str):
    """Compute statistical quality & accuracy metrics."""
    arr_orig = np.array(orig_img.convert('RGB'), dtype=np.float64)
    arr_enc = np.array(enc_img.convert('RGB'), dtype=np.float64)
    
    mse = np.mean((arr_orig - arr_enc) ** 2)
    psnr = float('inf') if mse == 0 else 20 * np.log10(255.0 / np.sqrt(mse))
    ssim_val = ssim(np.array(orig_img.convert('RGB')), np.array(enc_img.convert('RGB')), channel_axis=2)
    
    bin_orig = text_to_bin(orig_text)
    bin_ext = text_to_bin(ext_text)
    
    min_len = min(len(bin_orig), len(bin_ext))
    bit_errors = sum(b1 != b2 for b1, b2 in zip(bin_orig[:min_len], bin_ext[:min_len]))
    bit_errors += abs(len(bin_orig) - len(bin_ext))
    max_len = max(len(bin_orig), len(bin_ext))
    
    ber = (bit_errors / max_len) * 100 if max_len > 0 else 0.0
    return mse, psnr, ssim_val, ber


def get_attack_sweep(attack_type: str, steps: int = 10):
    """Return a list of strength values to test for a given attack type."""
    if attack_type == "JPEG Compression":
        return [int(v) for v in np.linspace(100, 1, steps)]
    if attack_type == "Gaussian Noise":
        return [round(float(v), 2) for v in np.linspace(0, 50, steps)]
    if attack_type == "Gaussian Blur":
        return [round(float(v), 2) for v in np.linspace(0, 5, steps)]
    if attack_type == "Rotation":
        return [round(float(v), 2) for v in np.linspace(0, 45, steps)]
    if attack_type == "Crop & Resize":
        return [round(float(v), 2) for v in np.linspace(1, 50, steps)]
    return [0]


def _safe_str(s: str) -> str:
    return s.encode("utf-8", errors="replace").decode("utf-8")


def sanitize_for_csv(s: str) -> str:
    """Strip characters that break CSV writing (nulls, control chars) and keep it CSV-safe."""
    if not s:
        return s
    cleaned = "".join(ch for ch in s if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    cleaned = cleaned.encode("utf-8", errors="replace").decode("utf-8")
    return cleaned


def run_single_case(cover_img, lsb_img, dct_img, secret_text, attack_type, strength):
    lsb_attacked = apply_attack(lsb_img, attack_type, strength)
    dct_attacked = apply_attack(dct_img, attack_type, strength)

    lsb_ext = LSBSteganography.decode(lsb_attacked)
    dct_ext = DCTSteganography.decode(dct_attacked)

    lsb_mse, lsb_psnr, lsb_ssim, lsb_ber = compute_metrics(cover_img, lsb_attacked, secret_text, lsb_ext)
    dct_mse, dct_psnr, dct_ssim, dct_ber = compute_metrics(cover_img, dct_attacked, secret_text, dct_ext)

    lsb_success = lsb_ext.strip() == secret_text.strip()
    dct_success = dct_ext.strip() == secret_text.strip()

    row = {
        "Attack": attack_type,
        "Strength": strength,
        "LSB MSE": lsb_mse,
        "LSB PSNR (dB)": None if lsb_psnr == float('inf') else round(lsb_psnr, 2),
        "LSB SSIM": lsb_ssim,
        "LSB BER (%)": round(lsb_ber, 2),
        "LSB Recovered OK": lsb_success,
        "LSB Extracted Message": sanitize_for_csv(lsb_ext) if lsb_ext else "(nothing recovered)",
        "DCT MSE": dct_mse,
        "DCT PSNR (dB)": round(dct_psnr, 2),
        "DCT SSIM": dct_ssim,
        "DCT BER (%)": round(dct_ber, 2),
        "DCT Recovered OK": dct_success,
        "DCT Extracted Message": sanitize_for_csv(dct_ext) if dct_ext else "(nothing recovered)",
    }
    return row, lsb_attacked, dct_attacked


def build_report_zip(cases: list) -> bytes:
    """cases: list of (row_dict, lsb_attacked_img, dct_attacked_img)"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for row, lsb_img_atk, dct_img_atk in cases:
            attack = row["Attack"].replace(" ", "_").replace("&", "and")
            strength = row["Strength"]
            tag = f"{attack}_s{strength}"

            lsb_bytes = image_to_bytes(lsb_img_atk, format="PNG")
            dct_bytes = image_to_bytes(dct_img_atk, format="PNG")

            zf.writestr(f"lsb/{tag}_lsb.png", lsb_bytes)
            zf.writestr(f"dct/{tag}_dct.png", dct_bytes)
    return buf.getvalue()


st.markdown("""
<div class="main-header">
    <h1>Comparison between LSB and DCT</h1>
    <p>Compare spatial domain (LSB) and frequency domain (DCT) image steganography side-by-side, including robustness under attack.</p>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.title("Controls")
    app_mode = st.radio("Select Mode", ["Encode & Compare", "Decode Message", "Full Report"], index=0)
    st.divider()
    st.markdown("### Domain Overview")
    st.caption("**LSB (Spatial):** Modifies pixel color bits directly. High capacity and high fidelity, but fragile against compression and edits.")
    st.caption("**DCT (Frequency):** Embeds bits in 8x8 frequency coefficients. Lower capacity, but more robust against image transformations.")


if app_mode == "Encode & Compare":
    st.subheader("Parallel Encoding, Attack Simulation & Metrics Comparison")
    
    col_input, col_preview = st.columns([1, 1], gap="large")
    
    with col_input:
        uploaded_file = st.file_uploader("1. Upload Cover Image", type=["png", "bmp"], key="enc_file")
        if uploaded_file:
            cover_img = Image.open(uploaded_file)
            width, height = cover_img.size
            
            lsb_cap_bytes = (width * height * 3 - 8) // 8
            dct_cap_bytes = ((width // 8) * (height // 8) * 3 - 8) // 8
            
            secret_text = st.text_area("2. Enter Secret Message", placeholder="Type your payload here...", height=120)
            current_bytes = len(secret_text.encode('utf-8'))
            
            st.caption(f"Payload Size: **{current_bytes:,} Bytes**")
            st.caption(f"• LSB Max Capacity: **{lsb_cap_bytes:,} Bytes**")
            st.caption(f"• DCT Max Capacity: **{dct_cap_bytes:,} Bytes**")
            
            attack_type = st.selectbox(
                "3. Attack Type",
                ["None", "JPEG Compression", "Gaussian Noise", "Gaussian Blur", "Rotation", "Crop & Resize"]
            )
            strength_labels = {
                "None": None,
                "JPEG Compression": ("JPEG Quality (lower = harsher)", 1, 100, 75),
                "Gaussian Noise": ("Noise Std Dev", 0.0, 50.0, 10.0),
                "Gaussian Blur": ("Blur Radius", 0.0, 5.0, 1.0),
                "Rotation": ("Rotation Angle (degrees)", -45.0, 45.0, 5.0),
                "Crop & Resize": ("Crop Percentage", 1.0, 50.0, 10.0),
            }
            attack_strength = 0.0
            if attack_type != "None":
                label, lo, hi, default = strength_labels[attack_type]
                attack_strength = st.slider(label, lo, hi, default)
            
            encode_btn = st.button("Process & Compare Both Methods", type="primary", use_container_width=True)

    with col_preview:
        if uploaded_file:
            st.image(cover_img, caption=f"1. Cover Image ({width}x{height} px)", use_container_width=True)

    if uploaded_file and secret_text and encode_btn:
        try:
            with st.spinner("Executing LSB and DCT algorithms..."):
                lsb_img = LSBSteganography.encode(cover_img, secret_text)
                dct_img = DCTSteganography.encode(cover_img, secret_text)

                lsb_ext_clean = LSBSteganography.decode(lsb_img)
                dct_ext_clean = DCTSteganography.decode(dct_img)
                lsb_mse, lsb_psnr, lsb_ssim, lsb_ber_clean = compute_metrics(cover_img, lsb_img, secret_text, lsb_ext_clean)
                dct_mse, dct_psnr, dct_ssim, dct_ber_clean = compute_metrics(cover_img, dct_img, secret_text, dct_ext_clean)

                lsb_attacked = apply_attack(lsb_img, attack_type, attack_strength)
                dct_attacked = apply_attack(dct_img, attack_type, attack_strength)

                lsb_ext_attacked = LSBSteganography.decode(lsb_attacked)
                dct_ext_attacked = DCTSteganography.decode(dct_attacked)

                _, _, _, lsb_ber_attacked = compute_metrics(cover_img, lsb_attacked, secret_text, lsb_ext_attacked)
                _, _, _, dct_ber_attacked = compute_metrics(cover_img, dct_attacked, secret_text, dct_ext_attacked)

                lsb_diff = ImageEnhance.Brightness(ImageChops.difference(cover_img.convert('RGB'), lsb_img.convert('RGB'))).enhance(50.0)
                dct_diff = ImageEnhance.Brightness(ImageChops.difference(cover_img.convert('RGB'), dct_img.convert('RGB'))).enhance(50.0)

            st.session_state["enc_results"] = {
                "attack_type": attack_type,
                "attack_strength": attack_strength,
                "lsb_img": lsb_img, "dct_img": dct_img,
                "lsb_mse": lsb_mse, "lsb_psnr": lsb_psnr, "lsb_ssim": lsb_ssim, "lsb_ber_clean": lsb_ber_clean,
                "dct_mse": dct_mse, "dct_psnr": dct_psnr, "dct_ssim": dct_ssim, "dct_ber_clean": dct_ber_clean,
                "lsb_attacked": lsb_attacked, "dct_attacked": dct_attacked,
                "lsb_ext_attacked": lsb_ext_attacked, "dct_ext_attacked": dct_ext_attacked,
                "lsb_ber_attacked": lsb_ber_attacked, "dct_ber_attacked": dct_ber_attacked,
                "lsb_diff": lsb_diff, "dct_diff": dct_diff,
            }
        except Exception as err:
            st.error(f"Processing error: {err}")
            st.session_state.pop("enc_results", None)

    if "enc_results" in st.session_state:
        r = st.session_state["enc_results"]

        st.divider()
        st.subheader("Method Comparison Metrics")
        st.caption(f"Attack applied before decoding: **{r['attack_type']}**" + (f" (strength: {r['attack_strength']})" if r['attack_type'] != "None" else ""))

        m1, m2 = st.columns(2)

        with m1:
            st.markdown("#### 🔹 LSB (Spatial Domain)")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("MSE", f"{r['lsb_mse']:.5f}")
            c2.metric("PSNR", "∞" if r['lsb_psnr'] == float('inf') else f"{r['lsb_psnr']:.2f} dB")
            c3.metric("SSIM", f"{r['lsb_ssim']:.5f}")
            c4.metric("BER (clean)", f"{r['lsb_ber_clean']:.2f}%")
            st.metric("BER after attack", f"{r['lsb_ber_attacked']:.2f}%")

            st.image(r['lsb_img'], caption="2. LSB Stego Image", use_container_width=True)
            st.download_button(
                label="Download LSB Stego Image",
                data=image_to_bytes(r['lsb_img']),
                file_name="stego_lsb.png",
                mime="image/png",
                use_container_width=True,
                key="dl_lsb_stego"
            )

            st.image(r['lsb_attacked'], caption=f"5a. LSB Altered Image ({r['attack_type']})", use_container_width=True)
            st.download_button(
                label="Download LSB Altered Image",
                data=image_to_bytes(r['lsb_attacked'], format="PNG"),
                file_name="altered_lsb.png",
                mime="image/png",
                use_container_width=True,
                key="dl_lsb_attacked"
            )
            st.text_area("LSB Extracted After Attack", value=r['lsb_ext_attacked'] if r['lsb_ext_attacked'] else "(nothing recovered)", height=80, key="ta_lsb")

            st.image(r['lsb_diff'], caption="LSB Difference (50x)", use_container_width=True)
            st.download_button(
                label="Download LSB Difference Map",
                data=image_to_bytes(r['lsb_diff']),
                file_name="diff_lsb_50x.png",
                mime="image/png",
                use_container_width=True,
                key="dl_lsb_diff"
            )

        with m2:
            st.markdown("#### 🔸 DCT (Frequency Domain)")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("MSE", f"{r['dct_mse']:.5f}")
            c2.metric("PSNR", f"{r['dct_psnr']:.2f} dB")
            c3.metric("SSIM", f"{r['dct_ssim']:.5f}")
            c4.metric("BER (clean)", f"{r['dct_ber_clean']:.2f}%")
            st.metric("BER after attack", f"{r['dct_ber_attacked']:.2f}%")

            st.image(r['dct_img'], caption="3. DCT Stego Image", use_container_width=True)
            st.download_button(
                label="Download DCT Stego Image",
                data=image_to_bytes(r['dct_img']),
                file_name="stego_dct.png",
                mime="image/png",
                use_container_width=True,
                key="dl_dct_stego"
            )

            st.image(r['dct_attacked'], caption=f"5b. DCT Altered Image ({r['attack_type']})", use_container_width=True)
            st.download_button(
                label="Download DCT Altered Image",
                data=image_to_bytes(r['dct_attacked'], format="PNG"),
                file_name="altered_dct.png",
                mime="image/png",
                use_container_width=True,
                key="dl_dct_attacked"
            )
            st.text_area("DCT Extracted After Attack", value=r['dct_ext_attacked'] if r['dct_ext_attacked'] else "(nothing recovered)", height=80, key="ta_dct")

            st.image(r['dct_diff'], caption="DCT Difference (50x)", use_container_width=True)
            st.download_button(
                label="Download DCT Difference Map",
                data=image_to_bytes(r['dct_diff']),
                file_name="diff_dct_50x.png",
                mime="image/png",
                use_container_width=True,
                key="dl_dct_diff"
            )


elif app_mode == "Decode Message":
    st.subheader("Decode Secret Message")
    
    col_dec_in, col_dec_out = st.columns([1, 1], gap="large")
    
    with col_dec_in:
        stego_file = st.file_uploader("Upload Stego Image", type=["png", "bmp"], key="dec_file")
        algo_choice = st.selectbox("Select Extraction Method", ["LSB (Spatial)", "DCT (Frequency)"])
        attack_type = st.selectbox(
            "Attack Type",
            ["None", "JPEG Compression", "Gaussian Noise", "Gaussian Blur", "Rotation", "Crop & Resize"]
        )
        strength_labels = {
            "None": None,
            "JPEG Compression": ("JPEG Quality (lower = harsher)", 1, 100, 75),
            "Gaussian Noise": ("Noise Std Dev", 0.0, 50.0, 10.0),
            "Gaussian Blur": ("Blur Radius", 0.0, 5.0, 1.0),
            "Rotation": ("Rotation Angle (degrees)", -45.0, 45.0, 5.0),
            "Crop & Resize": ("Crop Percentage", 1.0, 50.0, 10.0),
        }
        attack_strength = 0.0
        if attack_type != "None":
            label, lo, hi, default = strength_labels[attack_type]
            attack_strength = st.slider(label, lo, hi, default)
        apply_attack_before_decode = st.checkbox("Apply selected attack before decoding", value=False)
        
        if stego_file:
            stego_img = Image.open(stego_file)
            preview_img = apply_attack(stego_img, attack_type, attack_strength) if apply_attack_before_decode else stego_img
            st.image(preview_img, caption="Uploaded Image Preview" + (f" (attacked: {attack_type})" if apply_attack_before_decode else ""), use_container_width=True)
            decode_btn = st.button("Extract Message", type="primary", use_container_width=True)

    with col_dec_out:
        if stego_file and 'decode_btn' in locals() and decode_btn:
            st.markdown("**Extracted Payload**")
            with st.spinner("Decoding image..."):
                target_img = apply_attack(stego_img, attack_type, attack_strength) if apply_attack_before_decode else stego_img
                if "LSB" in algo_choice:
                    msg = LSBSteganography.decode(target_img)
                else:
                    msg = DCTSteganography.decode(target_img)
                
                if msg:
                    st.success("Extraction successful!")
                    st.text_area("Decrypted Message", value=msg, height=200)
                else:
                    st.warning("No message detected or payload was unreadable with this technique.")


elif app_mode == "Full Report":
    st.subheader("Robustness Report: All Attacks × All Strengths")
    st.caption("Uploads a cover image + secret text, encodes with LSB and DCT, then sweeps every attack type across a range of strengths and reports PSNR/BER/recovery success for both methods.")

    col_a, col_b = st.columns([1, 1], gap="large")

    with col_a:
        report_file = st.file_uploader("1. Upload Cover Image", type=["png", "bmp"], key="report_file")
        report_text = st.text_area("2. Enter Secret Message", placeholder="Type your payload here...", height=100, key="report_text")
        steps = st.slider("Steps per attack (resolution of sweep)", 3, 20, 8)
        include_attacks = st.multiselect(
            "Attacks to include",
            ["JPEG Compression", "Gaussian Noise", "Gaussian Blur", "Rotation", "Crop & Resize"],
            default=["JPEG Compression", "Gaussian Noise", "Gaussian Blur", "Rotation", "Crop & Resize"]
        )
        include_images_in_zip = st.checkbox("Include attacked images in downloadable ZIP", value=True)
        run_report = st.button("Generate Report", type="primary", use_container_width=True)

    if report_file:
        report_img = Image.open(report_file)
        with col_b:
            st.image(report_img, caption="Cover Image", use_container_width=True)

    if report_file and report_text and run_report:
        try:
            import pandas as pd

            with st.spinner("Encoding base stego images..."):
                lsb_base = LSBSteganography.encode(report_img, report_text)
                dct_base = DCTSteganography.encode(report_img, report_text)

            cases = []
            total_cases = sum(len(get_attack_sweep(a, steps)) for a in include_attacks) + 1
            progress = st.progress(0.0, text="Running sweep...")
            done = 0

            cases.append(run_single_case(report_img, lsb_base, dct_base, report_text, "None", 0))
            done += 1
            progress.progress(done / total_cases)

            for attack in include_attacks:
                for strength in get_attack_sweep(attack, steps):
                    cases.append(run_single_case(report_img, lsb_base, dct_base, report_text, attack, strength))
                    done += 1
                    progress.progress(done / total_cases, text=f"Running {attack} @ {strength}")

            progress.empty()

            df = pd.DataFrame([c[0] for c in cases])
            csv_bytes = df.to_csv(index=False, quoting=csv.QUOTE_ALL).encode("utf-8")
            zip_bytes = build_report_zip(cases) if include_images_in_zip else None

            st.session_state["report_results"] = {
                "df": df,
                "csv_bytes": csv_bytes,
                "zip_bytes": zip_bytes,
                "include_attacks": include_attacks,
            }
        except Exception as err:
            st.error(f"Report generation error: {err}")
            st.session_state.pop("report_results", None)

    if "report_results" in st.session_state:
        res = st.session_state["report_results"]
        df = res["df"]

        st.divider()
        st.subheader("Report Table")
        st.dataframe(
            df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "LSB Extracted Message": st.column_config.TextColumn(width="large"),
                "DCT Extracted Message": st.column_config.TextColumn(width="large"),
            }
        )

        dl1, dl2 = st.columns(2)
        with dl1:
            st.download_button(
                "Download Report as CSV",
                data=res["csv_bytes"],
                file_name="stego_robustness_report.csv",
                mime="text/csv",
                use_container_width=True,
                key="dl_report_csv"
            )
        with dl2:
            if res["zip_bytes"] is not None:
                st.download_button(
                    "Download Attacked Images (ZIP)",
                    data=res["zip_bytes"],
                    file_name="stego_attacked_images.zip",
                    mime="application/zip",
                    use_container_width=True,
                    key="dl_report_zip"
                )
            else:
                st.caption("Enable the checkbox above and regenerate to include image downloads.")

        st.divider()
        st.subheader("BER vs. Strength (per attack)")
        for attack in res["include_attacks"]:
            sub = df[df["Attack"] == attack]
            if sub.empty:
                continue
            st.markdown(f"**{attack}**")
            chart_df = sub.set_index("Strength")[["LSB BER (%)", "DCT BER (%)"]]
            st.line_chart(chart_df)