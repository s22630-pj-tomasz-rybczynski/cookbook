from flask_login import UserMixin
import json

class Recipe:
    def __init__(self, id, title, ingredients, instructions):
        self.id = id
        self.title = title
        self.ingredients = ingredients
        self.instructions = instructions


    def to_json(self):
        return json.dumps(self.__dict__)
    

class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password


    def to_json(self):
        return json.dumps(self.__dict__)