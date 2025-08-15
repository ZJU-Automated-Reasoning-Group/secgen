import os
from openai import OpenAI


class LLMInterface:
    def __init__(self, model: str = "deepseek-chat"):
        self.model = model
        
        if model.startswith("deepseek"):
            api_key = os.getenv("DEEPSEEK_API_KEY")
            if not api_key:
                raise ValueError("DEEPSEEK_API_KEY required")
            self.client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
        else:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OPENAI_API_KEY required")
            self.client = OpenAI(api_key=api_key)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.6
        )
        return response.choices[0].message.content
