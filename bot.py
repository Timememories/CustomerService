from textblob import TextBlob
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
import re
from ollama import Client

analyzer = SentimentIntensityAnalyzer()

client = Client(
    host="https://ollama.com",
    headers={'Authorization': 'Bearer 514179e47d2a48e38a9775ad04d7ea75.Qk3-lkKuuo8CTfLenJUQ0x53'}
)


def clean_text(text):
    return re.sub(r'[^\w\s]', ' ', text.lower()).strip()


def analyze_sentiment(text):
    try:
        blob = TextBlob(text)
        if blob.detect_language() == 'ru':
            text = str(blob.translate(to='en'))
    except:
        pass
    scores = analyzer.polarity_scores(text)
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
