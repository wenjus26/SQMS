import re

def validate_email(email):
    # Pattern regex pour valider un email
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Vérifier si l'email correspond au pattern regex
    if re.match(pattern, email):
        return True
    else:
        return False
    

def validate_name(name):
    # Pattern regex pour valider les prénoms et les noms de famille
    pattern = r'^[a-zA-Z]+$'
    
    # Vérifier si le nom correspond au pattern regex
    if re.match(pattern, name):
        return True
    else:
        return False
    

def validate_full_name(full_name):
    pattern = r'^[a-zA-Z]+ [a-zA-Z]+$'
    return bool(re.match(pattern, full_name))

    
def validate_container_number(container_number):
    # Pattern regex pour valider les numéros de conteneur
    pattern = r'^[A-Z]{4}\d{7}$'
    
    # Vérifier si le numéro de conteneur correspond au pattern regex
    if re.match(pattern, container_number):
        return True
    else:
        return False


def validate_truck_number(truck_number):
    patterns = [
        r'^[A-Z]\d{4}RB$',                     # Format: A1245RB
        r'^[A-Z]{2}\d{4}RB$',                  # Format: AA1234RB
        r'^[A-Z]\d{4}RB-[A-Z]\d{4}RB$',        # Format: A3345RB-A4567RB
        r'^[A-Z]{2}\d{4}RB-[A-Z]\d{4}RB$',     # Format: AA3345RB-A4567RB
        r'^[A-Z]\d{4}RB-[A-Z]{2}\d{4}RB$',     # Format: A3345RB-AA4567RB
        r'^[A-Z]{2}\d{4}RB-[A-Z]{2}\d{4}RB$'   # Format: AA3345RB-AA4567RB
    ]
    
    for pattern in patterns:
        if re.match(pattern, truck_number):
            return True
    return False

def validate_phone_number(phone_number):
    pattern = r'^[0-9]{8}$'
    return bool(re.match(pattern, phone_number))


def validate_booking_number(booking_number):
    # Pattern regex pour valider les numéros de réservation
    pattern = r'^[A-Z0-9]{3,10}$'
    
    # Vérifier si le numéro de réservation correspond au pattern regex
    if re.match(pattern, booking_number):
        return True
    else:
        return False



def validate_number(value):
    pattern = r'^[-+]?[0-9]*\.?[0-9]+$'  # Correspond à un nombre entier ou décimal avec une partie entière optionnelle, une partie fractionnaire optionnelle et un signe optionnel en début
    return bool(re.match(pattern, value))

def validate_password(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-_+=])[A-Za-z\d!@#$%^&*()-_+=]{6,}$'
    return bool(re.match(pattern, password))



