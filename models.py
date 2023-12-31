from flask_login import UserMixin
import json

class Recipe:
    def __init__(self, id, title, ingredients, instructions, image_address, user_id):
        self.id = id
        self.title = title
        self.ingredients = ingredients.split(",")
        self.instructions = instructions
        self.image_address = image_address
        self.user_id = user_id


    def to_json(self):
        return json.dumps(self.__dict__)
    

class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password


    def to_json(self):
        return json.dumps(self.__dict__)
