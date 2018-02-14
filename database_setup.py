import sys
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    __tablename__ = 'category'

    name =Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    
    
    

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
        }


class Item(Base):
    __tablename__ = 'item'

    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    description=Column(String(80), nullable=False)
    category_id = Column(Integer, ForeignKey('category.id'))
    category=relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    

    @property
    def serialize(self):
       return {'Item_name': self.name,'item_desc': self.description, 'Item_id': self.id, 'Item_category':self.category.name }
 

engine = create_engine('postgresql://catalogapp:password@localhost/catalog')
Base.metadata.create_all(engine)
