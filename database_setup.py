from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.dialects.sqlite import DATETIME
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key = True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(500))
    allow_public_access = Column(Integer, nullable=False)  # Feature not implemented yet
    signup_date = Column(DATETIME, default=datetime.datetime.utcnow)


class Region(Base):
    __tablename__ = 'region'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    picture = Column(String(500))
    geo_location = Column(String(500))
    rating = Column(Integer, nullable=False)
    creation_date = Column(DATETIME, default=datetime.datetime.utcnow)
    modifiy_date = Column(DATETIME, default=datetime.datetime.utcnow)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id'           : self.id,
           'name'         : self.name,
           'picture'       : self.picture,
           'geo_location'  : self.geo_location,
           'rating'  : self.rating,
           'creation_date'  : self.creation_date.strftime('%Y-%m-%d %H:%M:%S'),
           'modifiy_date'  : self.modifiy_date.strftime('%Y-%m-%d %H:%M:%S'),
           'user_id'      : self.user_id,
       }


    def visible_to_public(self):
      return self.user.allow_public_access == 1;

    def large_picture(self):
      return self.picture.replace(".jpg", "_lg.jpg");

 
class Place(Base):
    __tablename__ = 'place'

    id = Column(Integer, primary_key = True)
    name = Column(String(250), nullable = False)
    description = Column(String(2000))
    picture = Column(String(500))
    geo_location = Column(String(500))
    info_website = Column(String(500))
    rating = Column(Integer, nullable=False)
    creation_date = Column(DATETIME, default=datetime.datetime.utcnow)
    modifiy_date = Column(DATETIME, default=datetime.datetime.utcnow)
    region_id = Column(Integer,ForeignKey('region.id'))
    region = relationship(Region)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'id'           : self.id,
           'name'         : self.name,
           'description'   : self.description,
           'picture'       : self.picture,
           'geo_location'  : self.geo_location,
           'info_website'  : self.info_website,
           'rating'  : self.rating,
           'creation_date'  : self.creation_date.strftime('%Y-%m-%d %H:%M:%S'),
           'modifiy_date'  : self.modifiy_date.strftime('%Y-%m-%d %H:%M:%S'),
           'user_id'      : self.user_id,
       }

    def large_picture(self):
      return self.picture.replace(".jpg", "_lg.jpg");


engine = create_engine('sqlite:///travelbucketlist.db')
 

Base.metadata.create_all(engine)
