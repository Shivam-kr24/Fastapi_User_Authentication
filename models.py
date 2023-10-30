from sqlalchemy import Column, Integer, String, ForeignKey
from database import Base
from sqlalchemy.orm import relationship


class User(Base):
    __tablename__ = "user"
    # session.query(UserBase.column_name).filter(UserBase.some_column == value)

    id = Column(Integer, primary_key=True, index=True)
    Name = Column(String)
    Phone = Column(String)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    blogs = relationship("Blog", back_populates="owner")


class Blog(Base):
    __tablename__ = "blog"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    owner_id = Column(Integer, ForeignKey("user.id"))

    owner = relationship("User", back_populates="blogs")




