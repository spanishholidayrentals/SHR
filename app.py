from fastapi import FastAPI, Depends, HTTPException, status, Form
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
import bcrypt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List
from loguru import logger
from dotenv import load_dotenv
import os
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY")


logger.add("app.log", rotation="500 MB", level="INFO", backtrace=True, diagnose=True)

# Database setup
DATABASE_URL = "postgresql://postgres:NaRRmVpnSlbwqKTbWBYBWrdoRKkhdHKo@postgres.railway.internal:5432/railway"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI()

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# User model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")  # Default role is "user"

# Property model
class Property(Base):
    __tablename__ = "properties"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    location = Column(String, nullable=False)
    price_per_night = Column(Integer, nullable=False)
    created_by = Column(Integer, nullable=False)  # ID of the user who added the property

# Booking model
class Booking(Base):
    __tablename__ = "bookings"

    id = Column(Integer, primary_key=True, index=True)
    property_id = Column(Integer, nullable=False)
    user_id = Column(Integer, nullable=False)
    start_date = Column(String, nullable=False)
    end_date = Column(String, nullable=False)
    status = Column(String, default="confirmed")  # E.g., "confirmed", "cancelled"

# Create the database tables
@app.on_event("startup")
def create_tables():
    Base.metadata.create_all(bind=engine)

# Enforce permissions
def require_admin(current_user: User):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have the required permissions."
        )

# Helper function to hash passwords
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# Helper function to verify passwords
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# JWT Configuration
SECRET_KEY = "your_secret_key"  # Replace this with a secure random key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# OAuth2PasswordBearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Helper function to decode and validate the token
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# Endpoint to create a user
@app.post("/users/")
def create_user(username: str, email: str, password: str, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = hash_password(password)
    user = User(username=username, email=email, hashed_password=hashed_password)
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="User already exists")
    return user

# Endpoint to login and get a token
@app.post("/token/")
def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# Protected route to retrieve the current user's details
@app.get("/users/me/")
def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "email": current_user.email,
        "id": current_user.id
    }

# Admin-only endpoint
@app.get("/admin/")
def admin_dashboard(current_user: User = Depends(get_current_user)):
    require_admin(current_user)
    return {"message": "Welcome to the admin dashboard!"}

# Property management

# Pydantic model for creating properties
class PropertyCreate(BaseModel):
    name: str
    description: str
    location: str
    price_per_night: int

# Pydantic model for creating bookings
class BookingCreate(BaseModel):
    property_id: int
    start_date: str
    end_date: str

@app.post("/properties/")
def create_property(property: PropertyCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_admin(current_user)
    new_property = Property(
        name=property.name,
        description=property.description,
        location=property.location,
        price_per_night=property.price_per_night,
        created_by=current_user.id
    )
    db.add(new_property)
    db.commit()
    db.refresh(new_property)
    return new_property

@app.get("/properties/")
def get_properties(db: Session = Depends(get_db)):
    return db.query(Property).all()

@app.delete("/properties/{property_id}")
def delete_property(property_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_admin(current_user)
    property = db.query(Property).filter(Property.id == property_id).first()
    if not property:
        raise HTTPException(status_code=404, detail="Property not found")
    db.delete(property)
    db.commit()
    return {"message": f"Property {property_id} deleted successfully"}

# Create a booking
@app.post("/bookings/")
def create_booking(booking: BookingCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Ensure the property exists
    property = db.query(Property).filter(Property.id == booking.property_id).first()
    if not property:
        raise HTTPException(status_code=404, detail="Property not found")

    # Ensure the booking dates are valid
    start_date = datetime.strptime(booking.start_date, "%Y-%m-%d")
    end_date = datetime.strptime(booking.end_date, "%Y-%m-%d")
    if start_date >= end_date:
        raise HTTPException(status_code=400, detail="Invalid booking dates")

    # Check for overlapping bookings
    overlapping_booking = db.query(Booking).filter(
        Booking.property_id == booking.property_id,
        Booking.start_date < booking.end_date,
        Booking.end_date > booking.start_date
    ).first()
    if overlapping_booking:
        raise HTTPException(status_code=400, detail="Property is already booked for the selected dates")

    # Create the booking
    new_booking = Booking(
        property_id=booking.property_id,
        user_id=current_user.id,
        start_date=booking.start_date,
        end_date=booking.end_date
    )
    db.add(new_booking)
    db.commit()
    db.refresh(new_booking)
    return new_booking

# Get all bookings (admin only)
@app.get("/bookings/")
def get_all_bookings(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_admin(current_user)
    return db.query(Booking).all()

# Get bookings for the logged-in user
@app.get("/bookings/me/")
def get_my_bookings(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(Booking).filter(Booking.user_id == current_user.id).all()

@app.put("/bookings/{booking_id}/cancel/")
def cancel_booking(booking_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Retrieve the booking
    booking = db.query(Booking).filter(Booking.id == booking_id, Booking.user_id == current_user.id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")

    # Update the booking status
    if booking.status == "cancelled":
        raise HTTPException(status_code=400, detail="Booking is already cancelled")

    booking.status = "cancelled"
    db.commit()
    db.refresh(booking)
    return {"message": f"Booking {booking_id} has been cancelled"}

@app.get("/properties/search/")
def search_properties(location: str, start_date: str, end_date: str, db: Session = Depends(get_db)):
    logger.info(f"Search request received: location={location}, start_date={start_date}, end_date={end_date}")

    # Strip whitespace or newlines
    start_date = start_date.strip()
    end_date = end_date.strip()

    # Parse dates
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")
    except ValueError as e:
        logger.error(f"Date parsing error: {e}")
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD.")

    if start >= end:
        logger.warning(f"Invalid date range: start_date={start_date}, end_date={end_date}")
        raise HTTPException(status_code=400, detail="Invalid date range")

    # Find properties without overlapping bookings
    booked_property_ids = db.query(Booking.property_id).filter(
        Booking.start_date < end_date,
        Booking.end_date > start_date
    ).subquery()

    logger.info(f"Booked property IDs during the range: {booked_property_ids}")

    available_properties = db.query(Property).filter(
        Property.location.ilike(f"%{location}%"),
        ~Property.id.in_(booked_property_ids)
    ).all()

    if not available_properties:
        logger.info(f"No properties available for the criteria: location={location}, start_date={start_date}, end_date={end_date}")
        return {"message": "No properties available for the given criteria."}

    results = [
        {
            "id": prop.id,
            "name": prop.name,
            "description": prop.description,
            "location": prop.location,
            "price_per_night": prop.price_per_night,
            "created_by": prop.created_by
        }
        for prop in available_properties
    ]
    logger.info(f"Available properties returned: {results}")
    return results


# Endpoint: User's Upcoming Bookings
@app.get("/users/me/bookings/upcoming/", response_model=List[dict])
def get_upcoming_bookings(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    upcoming_bookings = db.query(Booking).filter(
        Booking.user_id == current_user.id,
        Booking.start_date >= datetime.utcnow().strftime("%Y-%m-%d")
    ).all()

    if not upcoming_bookings:
        logger.info(f"No upcoming bookings for user_id={current_user.id}")
        return {"message": "You have no upcoming bookings."}

    return [
        {
            "id": booking.id,
            "property_id": booking.property_id,
            "start_date": booking.start_date,
            "end_date": booking.end_date,
            "status": booking.status
        }
        for booking in upcoming_bookings
    ]

# Endpoint: User's Past Bookings
@app.get("/users/me/bookings/past/", response_model=List[dict])
def get_past_bookings(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    past_bookings = db.query(Booking).filter(
        Booking.user_id == current_user.id,
        Booking.end_date < datetime.utcnow().strftime("%Y-%m-%d")
    ).all()
    return [
        {
            "id": booking.id,
            "property_id": booking.property_id,
            "start_date": booking.start_date,
            "end_date": booking.end_date,
            "status": booking.status
        }
        for booking in past_bookings
    ]

# Endpoint: Cancel Booking
@app.put("/users/me/bookings/{booking_id}/cancel/")
def cancel_user_booking(booking_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    booking = db.query(Booking).filter(
        Booking.id == booking_id,
        Booking.user_id == current_user.id,
        Booking.start_date >= datetime.utcnow().strftime("%Y-%m-%d")
    ).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found or cannot be canceled.")
    if booking.status == "cancelled":
        raise HTTPException(status_code=400, detail="Booking is already cancelled.")

    booking.status = "cancelled"
    db.commit()
    db.refresh(booking)
    return {"message": f"Booking {booking_id} has been cancelled."}

# Endpoint: Admin - View All Properties
@app.get("/admin/properties/", response_model=List[dict])
def admin_view_properties(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_admin(current_user)
    properties = db.query(Property).all()
    return [
        {
            "id": prop.id,
            "name": prop.name,
            "location": prop.location,
            "price_per_night": prop.price_per_night,
            "description": prop.description,
            "created_by": prop.created_by
        }
        for prop in properties
    ]

# Endpoint: Admin - View All Bookings
@app.get("/admin/bookings/", response_model=List[dict])
def admin_view_bookings(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_admin(current_user)
    bookings = db.query(Booking).all()
    return [
        {
            "id": booking.id,
            "property_id": booking.property_id,
            "user_id": booking.user_id,
            "start_date": booking.start_date,
            "end_date": booking.end_date,
            "status": booking.status
        }
        for booking in bookings
    ]

# Endpoint: Admin - Delete a Property
@app.delete("/admin/properties/{property_id}/")
def admin_delete_property(property_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_admin(current_user)
    property = db.query(Property).filter(Property.id == property_id).first()
    if not property:
        raise HTTPException(status_code=404, detail="Property not found.")
    db.delete(property)
    db.commit()
    return {"message": f"Property {property_id} has been deleted."}

# Endpoint: Admin - Delete a Booking
@app.delete("/admin/bookings/{booking_id}/")
def admin_delete_booking(booking_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_admin(current_user)
    booking = db.query(Booking).filter(Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found.")
    db.delete(booking)
    db.commit()
    return {"message": f"Booking {booking_id} has been deleted."}


@app.get("/")
def read_root():
    return {"message": "App is working!"}
