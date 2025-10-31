# main.py
from aiogram import Bot, Dispatcher, executor, types
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from dotenv import load_dotenv
import os, json, re, asyncio, time
from pathlib import Path
from typing import Optional, Dict, List, Tuple

# ---------- Optional Gemini ----------
try:
    import google.generativeai as genai   # pip install -U google-generativeai
except Exception:
    genai = None

# ---------- .env loader ----------
def load_env() -> Optional[Path]:
    here = Path(__file__).resolve().parent
    for p in (here / ".env", here.parent / ".env", Path.cwd() / ".env"):
        if p.exists():
            load_dotenv(p, override=True)
            print(f"[ENV] Loaded: {p}")
            return p
    load_dotenv()
    print("[ENV] Loaded by default search")
    return None

load_env()

# ---------- Tokens / Keys ----------
BOT_TOKEN = (os.getenv("BOT_TOKEN") or "").strip().strip('"').strip("'")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set. Put it in .env as BOT_TOKEN=123:ABC")

# В .env можно задать:
# USE_GEMINI=1|0
# GEMINI_API_KEY=...
# GEMINI_MODEL=gemini-1.5-flash-8b (желательно лёгкая/доступная)
USE_GEMINI = (os.getenv("USE_GEMINI", "1").strip() not in {"0", "false", "False"})
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()
WANTED = [
    (os.getenv("GEMINI_MODEL") or "").strip() or "gemini-1.5-flash-8b",
    "gemini-1.5-flash-8b",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
    "gemini-pro",
]

_gemini_model: Optional[object] = None
_gemini_selected: Optional[str] = None

def _normalize_wanted_name(name: str) -> List[str]:
    name = (name or "").strip()
    return [name, f"models/{name}"] if name else []

if USE_GEMINI and genai and GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)

        # Получаем доступные модели, поддерживающие generateContent
        available: List[str] = []
        try:
            for m in genai.list_models():
                methods = set(getattr(m, "supported_generation_methods", []) or [])
                if "generateContent" in methods:
                    available.append(getattr(m, "name", ""))
        except Exception as e:
            print(f"[Gemini] list_models failed: {e}")

        if available:
            print("[Gemini] Available models supporting generateContent:")
            for n in available:
                print("  -", n)

        chosen: Optional[str] = None
        for want in WANTED:
            for candidate in _normalize_wanted_name(want):
                if any(x.endswith(candidate) or x == candidate for x in available):
                    chosen = next(x for x in available if x.endswith(candidate) or x == candidate)
                    break
            if chosen:
                break

        if not chosen and available:
            chosen = available[0]

        if chosen:
            _gemini_model = genai.GenerativeModel(chosen)
            _gemini_selected = chosen
            print(f"[Gemini] Configured model: {_gemini_selected}")
        else:
            print("[Gemini] No usable models found — AI disabled")
            _gemini_model = None

    except Exception as e:
        print(f"[Gemini] Init failed: {e}")
        _gemini_model = None
else:
    if not USE_GEMINI: print("[Gemini] disabled by USE_GEMINI")
    elif not genai:   print("[Gemini] SDK unavailable")
    elif not GEMINI_API_KEY: print("[Gemini] API key missing")
    _gemini_model = None

# ---------- Bot ----------
bot = Bot(token=BOT_TOKEN)
dp  = Dispatcher(bot)

# ---------- Data ----------
DATA_DIR       = Path(__file__).resolve().parent / "data"
KEYWORDS_FILE  = DATA_DIR / "scam_keywords.json"
EXAMPLES_FILE  = DATA_DIR / "examples.json"

def load_keywords() -> List[str]:
    try:
        with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        kws = data.get("keywords", [])
        return sorted(set(str(k).lower() for k in kws if isinstance(k, str)))
    except Exception as e:
        print(f"[KW] Fallback (error: {e})")
        return [
            "transfer","urgent","money","prize","win","grant","link","click",
            "переведи","срочно","подарок","грант","ссылка","пароль","банк",
            "лотерея","выиграл","данные"
        ]

KEYWORDS = load_keywords()
try:
    with open(EXAMPLES_FILE, "r", encoding="utf-8") as f:
        KB_EXAMPLES = json.load(f)
except Exception as e:
    print(f"[KB] Not loaded: {e}")
    KB_EXAMPLES = {}

# ---------- Simple memory ----------
LAST_MSGS: Dict[int, str] = {}

# ---------- Helpers ----------
def detect_lang(sample: str) -> str:
    for ch in sample or "":
        if "\u0400" <= ch <= "\u04FF":
            return "ru"
    return "en"

def _normalize(text: str) -> str:
    t = (text or "").lower()
    t = re.sub(r"[^\w\s]+", " ", t)        # убираем пунктуацию
    t = re.sub(r"\s+", " ", t).strip()
    # латиница -> похожие кириллические символы (против простых обходов)
    map_l2c = str.maketrans({"a":"а","e":"е","o":"о","p":"р","c":"с","x":"х","y":"у","k":"к","m":"м","h":"н","b":"в","t":"т"})
    return t.translate(map_l2c)

def looks_suspicious(text: str) -> Tuple[bool, List[str]]:
    t = _normalize(text)
    reasons: List[str] = []

    # 1) Ключевые слова
    hits = [kw for kw in KEYWORDS if kw and re.search(rf"\b{re.escape(kw)}\b", t)]
    if hits:
        reasons.append("found keywords: " + ", ".join(hits[:5]))

    # 2) Маркеры ссылок/шортнеров
    if any(m in t for m in ["http://","https://","t.me/","bit.ly","tinyurl","wa.me/","vk.cc","goo.gl","lnkd.in","link","ссылка","перейди"]):
        reasons.append("contains link/shortener")

    # 3) Суммы и валюта
    if re.search(r"\b\d{1,3}(?:[\s.,\u00A0]\d{3})*(?:[.,]\d+)?\s?(?:₸|тенге|kzt|\$|usd|eur|€|руб|₽)\b", t):
        reasons.append("mentions money amount + currency")

    # 4) Команда + вознаграждение
    actions = ["click","кликни","перейди","введи","подтверди","переведи","оплати","follow","open","confirm"]
    rewards = ["выиграл","приз","подарок","лотерея","grant","грант","win","prize","reward","деньги","доход","инвестиция"]
    if any(re.search(rf"\b{re.escape(a)}\b", t) for a in actions) and any(re.search(rf"\b{re.escape(r)}\b", t) for r in rewards):
        reasons.append("action + reward pattern")

    return (len(reasons) > 0, reasons)

# ---------- Gemini helper with cooldown & fallback ----------
_ai_cooldown_until = 0.0
_ai_backoff_sec    = 60.0
_ai_backoff_max    = 3600.0  # до 1 часа

def _local_fallback_tip(lang: str) -> str:
    return (
        "Проверьте отправителя по официальному номеру, не переходите по ссылкам и не вводите данные. "
        "Если просят деньги/код — это почти наверняка мошенники."
        if lang == "ru" else
        "Verify the sender via official phone, don’t open links or enter credentials. "
        "If they ask for money/codes — it’s almost certainly a scam."
    )

async def ai_explain_safety(text: str, lang: str) -> Optional[str]:
    global _ai_cooldown_until, _ai_backoff_sec

    # Если модели нет или кулдаун — вернём локальный краткий совет
    if not _gemini_model or time.time() < _ai_cooldown_until:
        return _local_fallback_tip(lang)

    prompt = (
        "You are a concise financial safety assistant. In 1–2 sentences, explain why the user's message could be a scam and what to do next. Keep it actionable."
        if lang == "en" else
        "Ты краткий помощник по финансовой безопасности. За 1–2 предложения объясни, почему сообщение может быть мошенническим, и что делать дальше. Кратко и по делу."
    )
    payload = (text or "")[:1500]  # чуть короче, чтобы не упираться в лимиты токенов

    def _call():
        print("[Gemini] sent …")
        resp = _gemini_model.generate_content(prompt + "\n\nUser message:\n" + payload)
        out  = (getattr(resp, "text", "") or "").strip()
        print(f"[Gemini] response: {out[:200]}…" if out else "[Gemini] empty")
        return out

    try:
        out = await asyncio.to_thread(_call)
        return out[:500] if out else _local_fallback_tip(lang)
    except Exception as e:
        msg = str(e)
        # 429/квоты — выставляем кулдаун (пытаемся вытащить retry_delay)
        if "429" in msg or "quota" in msg.lower():
            m = re.search(r"retry[_ ]delay[^\d]*(\d+)", msg, flags=re.I)
            retry = float(m.group(1)) if m else _ai_backoff_sec
            _ai_cooldown_until = time.time() + min(retry, _ai_backoff_max)
            _ai_backoff_sec = min(_ai_backoff_sec * 2, _ai_backoff_max)  # экспоненциальный рост
            print(f"[Gemini] 429 -> cooldown {int(_ai_cooldown_until - time.time())}s")
        else:
            print(f"[Gemini] error: {e}")
        return _local_fallback_tip(lang)

# ---------- UI helpers ----------
def tips_text(lang: str) -> str:
    return ("💡 *Советы по безопасности:*\n"
            "• Никогда не передавайте личные данные через неизвестные ссылки.\n"
            "• Проверяйте отправителя, звоните в банк по официальному номеру.\n"
            "• Не переводите деньги по просьбе «родственника» без проверки.\n"
            "• Не переходите по укороченным ссылкам из незнакомых источников."
            if lang == "ru" else
            "💡 *Safety tips:*\n"
            "• Never share personal data via unknown links.\n"
            "• Verify the sender; call your bank through the official number.\n"
            "• Don’t send money to “relatives” without verification.\n"
            "• Avoid shortened links from unknown sources.")

def inline_kb(lang: str) -> InlineKeyboardMarkup:
    if lang == "ru":
        help_btn  = InlineKeyboardButton("📘 Советы", callback_data="help")
        report_btn= InlineKeyboardButton("🚩 Пожаловаться", callback_data="report")
    else:
        help_btn  = InlineKeyboardButton("📘 Tips", callback_data="help")
        report_btn= InlineKeyboardButton("🚩 Report", callback_data="report")
    return InlineKeyboardMarkup().add(help_btn, report_btn)

# ---------- Handlers ----------
@dp.message_handler(commands=["start"])
async def cmd_start(message: types.Message):
    lang = "ru" if detect_lang(message.from_user.language_code or "") == "ru" else "en"
    text = ("👋 Привет! Я *FinSafeBot* — ассистент по финансовой безопасности.\n"
            "Отправь мне любое сообщение, и я подскажу, не похоже ли оно на мошенничество."
            if lang == "ru" else
            "👋 Hello! I’m *FinSafeBot* — your financial safety assistant.\n"
            "Send me any message and I’ll help you check if it might be a scam.")
    await message.answer(text, parse_mode="Markdown", reply_markup=inline_kb(lang))

@dp.message_handler(commands=["help"])
async def cmd_help(message: types.Message):
    lang = detect_lang((message.text or "") + (message.from_user.language_code or ""))
    await message.answer(tips_text(lang), parse_mode="Markdown")

@dp.message_handler(commands=["examples"])
async def cmd_examples(message: types.Message):
    lang = detect_lang((message.text or "") + (message.from_user.language_code or ""))
    if not KB_EXAMPLES:
        await message.answer("Примеры не загружены." if lang == "ru" else "No examples loaded.")
        return
    header = "📚 Примеры мошенничества:" if lang == "ru" else "📚 Scam examples:"
    lines = [f"• {k}: {v}" for k, v in KB_EXAMPLES.items()]
    await message.answer(header + "\n" + "\n".join(lines))

@dp.callback_query_handler(lambda c: c.data in {"help","report"})
async def callbacks(call: types.CallbackQuery):
    lang = detect_lang((call.message.text or "") + (call.from_user.language_code or ""))
    uid  = call.from_user.id
    if call.data == "help":
        await call.answer(cache_time=0)
        text = tips_text(lang)
        last = LAST_MSGS.get(uid)
        if last:
            tip = await ai_explain_safety(last, lang)
            if tip:
                text += ("\n\n🤖 AI: " + tip)
        await call.message.answer(text, parse_mode="Markdown")
    else:
        text = ("✅ Заявка зафиксирована локально (демо). Обратитесь в ваш банк/КЦ при необходимости."
                if lang == "ru" else
                "✅ Report noted locally (demo). Contact your bank/call center if needed.")
        await call.answer("OK", show_alert=False)
        await call.message.answer(text)

@dp.message_handler()
async def analyze(message: types.Message):
    txt  = message.text or ""
    lang = detect_lang(txt)
    LAST_MSGS[message.from_user.id] = txt

    suspicious, reasons = looks_suspicious(txt)
    if lang == "ru":
        if suspicious:
            resp = ("⚠️ Сообщение выглядит *подозрительно*.\n"
                    "Не переходите по ссылкам и не отправляйте деньги. Проверьте источник!\n"
                    + ("Причина: " + "; ".join(reasons) if reasons else ""))
            tip = await ai_explain_safety(txt, lang)
            if tip: resp += "\n🤖 AI: " + tip
        else:
            resp = "✅ Признаков мошенничества не обнаружено."
    else:
        if suspicious:
            resp = ("⚠️ This message looks *suspicious*.\n"
                    "Do not click links or send money. Please verify the source!\n"
                    + ("Reason: " + "; ".join(reasons) if reasons else ""))
            tip = await ai_explain_safety(txt, lang)
            if tip: resp += "\n🤖 AI: " + tip
        else:
            resp = "✅ No suspicious activity detected."
    await message.answer(resp, parse_mode="Markdown", reply_markup=inline_kb(lang))

# ---------- Run ----------
if __name__ == "__main__":
    print("✅ FinSafeBot is starting…")
    executor.start_polling(dp, skip_updates=True)
