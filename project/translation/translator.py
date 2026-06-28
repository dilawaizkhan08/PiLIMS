from transformers import MarianTokenizer
from transformers import MarianMTModel

MODEL = "Helsinki-NLP/opus-mt-en-ar"

tokenizer = MarianTokenizer.from_pretrained(MODEL)
model = MarianMTModel.from_pretrained(MODEL)


def translate(text):

    if not text:
        return text

    tokens = tokenizer(
        text,
        return_tensors="pt",
        truncation=True
    )

    generated = model.generate(**tokens)

    return tokenizer.decode(
        generated[0],
        skip_special_tokens=True
    )