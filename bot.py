import re
from collections import Counter

from ollama import Client
from deep_translator import GoogleTranslator
from textblob.exceptions import TranslatorError
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from langdetect import detect, LangDetectException  # 替代TextBlob的语言检测

analyzer = SentimentIntensityAnalyzer()

client = Client(
    host="https://ollama.com",
    headers={'Authorization': 'Bearer 514179e47d2a48e38a9775ad04d7ea75.Qk3-lkKuuo8CTfLenJUQ0x53'}
)


def clean_text(text):
    return re.sub(r'[^\w\s]', ' ', text.lower()).strip()


def analyze_sentiment(text):
    """
    分析文本情感，返回VADER的compound得分（-1~1）
    逻辑：俄语→翻译为英语→情感分析，异常时使用原文本
    """
    # 边界处理：空文本/非字符串返回中性（0.0）
    if not isinstance(text, str) or text.strip() == "":
        return 0.0

    processed_text = text
    try:
        # 步骤1：用langdetect检测语言（替代TextBlob的detect_language）
        detected_lang = detect(text)
        if detected_lang in ['ru', 'bg']:
            # 使用deep-translator翻译（稳定且不易限流）
            processed_text = GoogleTranslator(
                source=detected_lang,  # 源语言（ru=俄语，bg=保加利亚语）
                target='en'  # 目标语言：英语
            ).translate(text)
    except LangDetectException:
        # 语言检测失败：使用原文本
        print(f"警告：无法检测文本语言（文本片段：{text[:50]}...）")
    except TranslatorError:
        # 翻译失败：使用原文本
        print(f"警告：俄语翻译失败（文本片段：{text[:50]}...）")
    except Exception as e:
        # 其他意外异常：记录并使用原文本
        print(f"文本处理异常：{str(e)}（文本片段：{text[:50]}...）")

    # 步骤3：情感分析并返回compound得分
    scores = analyzer.polarity_scores(processed_text)
    return scores['compound']


def contains_word(text, words):
    return any(word in text for word in words)


def generate_bot_response(text, sentiment):
    text_clean = clean_text(text)

    system_prompt = f"""
You are a helpful, empathetic, and professional customer support assistant.
Your goal is to provide accurate, clear, and friendly responses to users.
Consider the user's sentiment when crafting your reply: 
- If sentiment is very negative (< -0.7), be apologetic and offer immediate escalation.
- If sentiment is negative (-0.7 to -0.1), be understanding and ask for more details.
- If sentiment is positive (> 0.1), be cheerful and encouraging.
- If sentiment is neutral (~0), respond based on the context of the message.

User's message: "{text}"
User's sentiment score: {sentiment:.2f}

Please respond appropriately to the user's message, keeping your tone consistent with their sentiment.
"""
    messages = [
        {'role': 'system', 'content': system_prompt},
        {'role': 'user', 'content': text}
    ]

    try:
        response_parts = []
        for part in client.chat('gpt-oss:120b', messages=messages, stream=True):
            response_parts.append(part['message']['content'])

        full_response = ''.join(response_parts)
        return full_response.strip()

    except Exception as e:
        return f"Извините, произошла ошибка при обращении к сервису. Пожалуйста, попробуйте позже. Ошибка: {str(e)}"


def extract_keywords(text, top_n=5):
    # 清理文本
    text = re.sub(r'[^\w\s]', '', text.lower())
    # 过滤停用词
    stop_words = ['the', 'a', 'an', 'and', 'or', 'but', 'is', 'are', 'in', 'on', 'at']
    words = [word for word in text.split() if word not in stop_words and len(word) > 2]
    # 统计词频
    word_counts = Counter(words)
    return [word for word, _ in word_counts.most_common(top_n)]


# 会话摘要生成（简单版）
def generate_summary(text, max_length=100):
    sentences = re.split(r'[.!?]', text)
    # 取前N个非空句子
    valid_sentences = [s.strip() for s in sentences if s.strip()]
    summary = ' '.join(valid_sentences[:3])
    if len(summary) > max_length:
        summary = summary[:max_length] + '...'
    return summary if summary else 'No content to summarize'
