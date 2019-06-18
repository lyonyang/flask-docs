# Flask-Docs

## 安装


```shell
$ pip install Flask-API-Docs
```

## Hello World

```python
from flask import Flask
from flask_docs import Docs, register_docs, View


class Hello(View):
    @register_docs('/hello/')
    def get(self):
        return "Hello World"


app = Flask(__name__)
docs = Docs(app)

if __name__ == '__main__':
    app.run()

```

