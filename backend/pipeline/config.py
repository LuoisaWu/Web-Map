import os
import torch
from dotenv import load_dotenv

load_dotenv()

# ── Device detection ──────────────────────────────────────────────
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
GPU_NAME = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "N/A"
IS_GPU = DEVICE == "cuda"
USE_BF16 = IS_GPU and torch.cuda.is_bf16_supported()
USE_AMP_DTYPE = "bfloat16" if USE_BF16 else "float16"

# ── Data Paths ────────────────────────────────────────────────────
RAW_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "results_full.csv")

# Phase 1: diversity pool (all LLM-labeled together)
POOL_DATA_PATH = os.path.join(os.path.dirname(__file__), "dataset_pool.csv")
POOL_PREPROCESSED_PATH = os.path.join(os.path.dirname(__file__), "dataset_pool_preprocessed.csv")
POOL_LABELED_PATH = os.path.join(os.path.dirname(__file__), "dataset_pool_labeled.csv")

# Phase 2: stratified splits (post-labeling)
TRAIN_LABELED_PATH = os.path.join(os.path.dirname(__file__), "dataset_train_labeled.csv")
VAL_LABELED_PATH = os.path.join(os.path.dirname(__file__), "dataset_val_labeled.csv")
TEST_LABELED_PATH = os.path.join(os.path.dirname(__file__), "dataset_test_labeled.csv")

# Inference (unlabeled remainder)
INFERENCE_DATA_PATH = os.path.join(os.path.dirname(__file__), "dataset_inference.csv")
INFERENCE_PREPROCESSED_PATH = os.path.join(os.path.dirname(__file__), "dataset_inference_preprocessed.csv")
FINAL_INFERENCE_OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "results_final_predicted.csv")

# Model Save Path
MODEL_SAVE_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
BEST_MODEL_PATH = os.path.join(MODEL_SAVE_DIR, "best_student_model")

# ── Sampling config ───────────────────────────────────────────────
TARGET_POOL_SIZE = 17000        # total records to LLM-label
TRAIN_RATIO = 0.80
VAL_RATIO = 0.10
TEST_RATIO = 0.10
MIN_SAMPLES_PER_TAG_IN_EVAL = 8  # tags with fewer samples skip val/test

# ── DeepSeek Configuration ────────────────────────────────────────
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
DEEPSEEK_MODEL = "deepseek-v4-flash"

# ── Student Model Configuration ───────────────────────────────────
# English BERT — the text features are predominantly English
# (Server headers, SSL subjects, domain names, and most Titles)
STUDENT_MODEL_NAME = "microsoft/deberta-v3-base"
MAX_SEQ_LENGTH = 512

# ── Training hyperparams — auto-select by device ──────────────────
if IS_GPU:
    BATCH_SIZE = 64
    GRADIENT_ACCUMULATION_STEPS = 1
    EPOCHS = 15
    QUICK_TRAIN_SAMPLES = None
else:
    BATCH_SIZE = 16
    GRADIENT_ACCUMULATION_STEPS = 2
    EPOCHS = 1
    QUICK_TRAIN_SAMPLES = 500

LEARNING_RATE = 3e-5
LR_WARMUP_RATIO = 0.1
WEIGHT_DECAY = 0.01
MAX_GRAD_NORM = 1.0
PATIENCE = 5
USE_CLASS_WEIGHTS = True  # pos_weight for BCE loss

MULTI_LABEL_THRESHOLD = 0.5

# ── Tag system (v2 — merged & de-duplicated) ─────────────────────
#
# Three-layer architecture:
#   1. FUNCTIONAL — semantic website categories (ML model)
#   2. RISK       — content risk flags (ML model)
#   3. INFRASTRUCTURE — deployment/architecture (rule engine, NOT ML)
#
# Merged from original 57 tags down to 24 ML + 7 rule-based = 31 total.

TAGS_FUNCTIONAL = {
    # ── Information & Content ──
    "News": "新闻媒体/博客",             # merged: Blog
    "Academic": "学术/百科/图书",
    # ── Social & Communication ──
    "Social": "社交/通讯/直播",
    # ── Commerce & Business ──
    "Ecommerce": "电商",
    "Corporate": "企业官网",
    "Finance": "金融/保险/加密货币",
    "BusinessService": "商业服务/招聘",    # merged: Career
    # ── Lifestyle & Services ──
    "ConsumerService": "生活/消费/医疗/出行/运动", # merged: Healthcare, Travel, FoodLifestyle, Sports, RealEstate, Automotive
    "Education": "教育机构",
    # ── Government & Organizations ──
    "Government": "政府/公共/公益组织",   # merged: NGO
    # ── Technology ──
    "TechPlatform": "科技/开发/云服务",    # merged: DeveloperPlatform, CloudStorage
    "Security": "安全/VPN",
}

TAGS_RISK = {
    "Adult": "成人内容",
    "Gambling": "赌博博彩",
}

# Infrastructure tags — detected via HTTP header rules, NOT by the ML model.
# These are cheap to detect with near-perfect accuracy:
#   CDN: Server header (cloudflare, Akamai, CloudFront...), Via, CF-Ray
#   WAF: WAF_Detect field already present in raw data
#   Hosting: Server + reverse-DNS heuristics
#   CloudService: IP range / reverse-DNS
#   StaticSite: content-type + lack of dynamic indicators
#   API: content-type: application/json, path patterns
#   DNS: DNS_MX/DNS_NS fields in raw data
TAGS_INFRASTRUCTURE = {
    "CDN": "CDN",
    "WAF": "WAF",
    "Hosting": "托管服务",
    "CloudService": "云服务",
    "StaticSite": "静态网站",
    "API": "API服务",
    "DNS": "DNS服务",
}

# Combined lists for different contexts
ML_TAGS = {}
ML_TAGS.update(TAGS_FUNCTIONAL)
ML_TAGS.update(TAGS_RISK)

CATEGORIES = list(ML_TAGS.keys())          # 24 ML-predicted tags
NUM_LABELS = len(CATEGORIES)
INFRA_CATEGORIES = list(TAGS_INFRASTRUCTURE.keys())  # 7 rule-based tags
ALL_CATEGORIES = CATEGORIES + INFRA_CATEGORIES       # 31 total

# Mapping from original fine-grained tags → merged tags (for LLM prompt)
ORIGINAL_TO_MERGED = {
    # Functional
    "News": "News", "Blog": "News",
    "Wiki": "Academic", "Literature": "Academic", "Academic": "Academic",
    "SearchEngine": "TechPlatform",
    "SocialMedia": "Social", "Forum": "Social", "IM": "Social",
    "Dating": "Social", "Email": "Social", "LiveStreaming": "Social",
    "Ecommerce": "Ecommerce", "Corporate": "Corporate",
    "Banking": "Finance", "Insurance": "Finance",
    "Payment": "Finance", "Crypto": "Finance",
    "RealEstate": "ConsumerService", "Automotive": "ConsumerService",
    "Recruitment": "BusinessService", "Training": "BusinessService",
    "AdMarketing": "BusinessService", "Logistics": "BusinessService",
    "Legal": "BusinessService", "DomainRegistrar": "BusinessService",
    "Healthcare": "ConsumerService",
    "Travel": "ConsumerService", "Weather": "ConsumerService", "Navigation": "ConsumerService",
    "Food": "ConsumerService", "Fashion": "ConsumerService", "HomeDecor": "ConsumerService",
    "Education": "Education", "Sports": "ConsumerService", "FoodLifestyle": "ConsumerService",
    "Government": "Government", "PublicInstitution": "Government",
    "Military": "Government", "PoliticalParty": "Government",
    "NGO": "Government",
    "DeveloperPlatform": "TechPlatform",
    "AITool": "TechPlatform", "DataService": "TechPlatform",
    "SoftwareDownload": "TechPlatform", "IoT": "TechPlatform",
    "Security": "Security", "VPN": "Security",
    "CloudStorage": "TechPlatform",
    # Risk
    "Adult": "Adult", "Gambling": "Gambling",
    # Infrastructure (rule-based, but may still appear in LLM output)
    "CDN": "CDN", "WAF": "WAF", "Hosting": "Hosting",
    "CloudService": "CloudService", "StaticSite": "StaticSite",
    "API": "API", "DNS": "DNS",
}
