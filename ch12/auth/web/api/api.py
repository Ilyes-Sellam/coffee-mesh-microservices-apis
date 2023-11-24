from auth.web.app import app
from auth.web.api.schema import UserRegister, UserLogin
from auth.repository.models import User, SessionLocal
from auth.utils import jwt_service

import jwt
from sqlalchemy.orm import Session
from fastapi.exceptions import HTTPException
from fastapi import Depends, Cookie
from fastapi.responses import JSONResponse
from starlette.requests import Request


# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post('/register', status_code=201)
async def register(payload: UserRegister, db: Session = Depends(get_db)):
    user = User(firstname=payload.firstname, lastname=payload.lastname, email=payload.email, password=payload.password)
    exist = db.query(User).filter(User.email == user.email).first()
    if exist:
        raise HTTPException(status_code=404, detail='User with this email already exists')
    db.add(user)
    db.commit()
    confirmation_token = jwt_service.generate_confirmation_token(sub=user.id)
    print(confirmation_token)

    return JSONResponse(
                content={
                    'message': 'User created, now you must confirm your email',
                    'user': user.to_dict()
                }
        )


@app.get('/confirmation/{token}', status_code=204)
def confirmation(token: str):
    try:
        # Decode the confirmation token to get the user ID
        user_id = jwt_service.decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail='Confirmation token has expired')
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail='Invalid confirmation token')

    # Find the user in the database based on the user ID
    db = SessionLocal()
    user_to_confirm = db.query(User).filter(User.id == user_id).first()
    if user_to_confirm is None:
        raise HTTPException(status_code=404, detail='User not found for confirmation')

    # Update the user's 'is_activated' status to True
    user_to_confirm.is_activated = True

    # Commit the changes to the database
    db.commit()

    return None


@app.post('/login')
async def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    if user is None or not jwt_service.verify_password(payload.password, user.password):
        raise HTTPException(status_code=401, detail='Invalid Credentials')

    access_token = jwt_service.generate_access_token(sub=user.id)
    refresh_token = jwt_service.generate_refresh_token(sub=user.id)

    user.refresh_token = refresh_token
    db.commit()
    
    # Create a JSONResponse instance
    response = JSONResponse(content={
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer',
    })
    print('---------------------- access token:\n', access_token)
    print('---------------------- refresh token:\n', refresh_token)
    # Set the refresh token in a cookie for the web app
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=60 * 60 * 24 * 7,  # 7 days
        secure=False,  # Set to True if using HTTPS
        samesite="strict",
    )

    return response


@app.get('/logout', status_code=204)
def logout(
    request: Request,
    db: Session = Depends(get_db)
):
    user_id = request.state.user_id
    user = db.query(User).filter(User.id == user_id).first()
    refresh_token = request.cookies.get('refresh_token')
    # Check if the received refresh token matches the one stored in the database
    if user.refresh_token == refresh_token:
        response = JSONResponse(
                content=None,
            )
        response.delete_cookie(key="refresh_token")

        user.refresh_token = None
        db.commit()

        return JSONResponse(content={"message": "Logout successful"})
    else:
        raise HTTPException(status_code=401, detail="Invalid refresh token")


@app.get('/refresh', status_code=200)
def refresh(
    request: Request,
    db: Session = Depends(get_db)
):
    refresh_token = request.cookies.get('refresh_token')
    
    # Validate the refresh token against the stored tokens in the database
    user_id = jwt_service.verify_refresh_token(refresh_token, db)
    if not user_id:
        raise HTTPException(status_code=401, detail='Invalid refresh token')

    # Generate a new access token
    access_token = jwt_service.generate_access_token(sub=user_id)

    return {
        'access_token': access_token,
        'token_type': 'bearer',
    }
