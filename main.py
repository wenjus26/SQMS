# All Import statements
from flask import Flask, render_template, request, redirect, send_file, url_for ,flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user, user_accessed
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os, string, random
from functools import wraps
from sqlalchemy import extract, func, not_ , or_
import pandas as pd
from validators import validate_full_name, validate_number, validate_phone_number, validate_truck_number
from models import db, User,   Role, LogAction, TruckSample, PeripheralSample, MasterSample, FirstDecision, FinalDecision
#Initialized flask app with default settings for security purposes only and should be called before anything else is called from flask       

app = Flask(__name__, static_folder='static')
app.secret_key = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sqms.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  

#Initialisation of my database
db.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from datetime import datetime

def log_action(user_id, username, action, entry_code=None):
    if entry_code is None:
        entry_code = "No entry code"
    time = datetime.now()
    new_action = LogAction(user_id=user_id, username=username, action=action, entry_code=entry_code, time=time)
    db.session.add(new_action)
    db.session.commit()


# Fonction pour récupérer les informations de l'utilisateur actuellement connecté
def get_user_info():
    if current_user.is_authenticated:
        return {
            'username': current_user.username,
            'full_name': current_user.full_name,
            'email': current_user.email,
            'location': current_user.location,
            'profile_photo': current_user.profile_photo,
            # Ajoutez d'autres informations de l'utilisateur ici
        }
    else:
        return None

# Ajoutez le contexte global pour les informations de l'utilisateur
@app.context_processor
def inject_user_info():
    return dict(user_info=get_user_info())

def role_required(*role_names):
    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            # Check if user is logged in and has the required role
            if current_user.is_authenticated:
                user_roles = [role.name for role in current_user.roles]
                if any(role in user_roles for role in role_names):
                    return func(*args, **kwargs)
            flash('Access denied! Please contact the system admin.', 'error')
            return redirect(request.referrer or url_for('home'))
        return decorated_function
    return decorator  
@app.route('/')
@login_required 
def home():
    # Vérifie si l'utilisateur est connect
    if current_user:
        roles = [role.name for role in current_user.roles]
        return render_template('home.html',  username=current_user.username, roles=roles)
    
    # Redirige vers la page de connexion si l'utilisateur n'est pas connecté ou n'existe pas
    return redirect(url_for('login'))

from flask import make_response

@role_required('admin','Manager','Inspector')
@app.route('/export-logs-to-excel')
def export_logs_to_excel():
    # Récupérer toutes les entrées de journal depuis la base de données
    logs = LogAction.query.all()

    # Créer un DataFrame à partir des entrées de journal
    log_data = {
        'User ID': [log.user_id for log in logs],
        'Username': [log.username for log in logs],
        'Action': [log.action for log in logs],
        'Entry Code': [log.entry_code for log in logs],
        'Timestamp': [log.time.strftime("%Y-%m-%d %H:%M:%S") for log in logs],  # Formatage de la colonne time
    }
    df = pd.DataFrame(log_data)

    # Créer un objet BytesIO pour stocker le fichier Excel en mémoire
    excel_file = BytesIO()

    # Exporter le DataFrame vers le fichier Excel en mémoire
    df.to_excel(excel_file, index=False)

    # Revenir au début du fichier BytesIO
    excel_file.seek(0)

    # Créer une réponse HTTP avec le contenu du fichier Excel en mémoire
    response = make_response(excel_file.getvalue())

    # Définir les en-têtes de la réponse
    response.headers['Content-Disposition'] = 'attachment; filename=logs.xlsx'
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

    return response

                        
# Authentification of the user for  login and logout
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            log_action(current_user.id, current_user.username, 'logged in')
            flash('Logged in successfully.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('admin/authentification/login.html')

 

    
@app.route('/logout')
@login_required
def logout():
    log_action(current_user.id, current_user.username, 'Logged out')
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# Register a new user with the specified email address and password and redirect to the login page

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST': 
        full_name = request.form['full_name']
        location = request.form['location']
        position = request.form['position']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        existing_user_count = User.query.count()
        if existing_user_count == 0:
            admin_role = Role(name='admin')
            db.session.add(admin_role)
            db.session.commit()
            new_user = User(full_name= full_name, location = location,position = position , username=username, email=email, password=hashed_password)
            new_user.roles.append(admin_role)
        else:
            new_user = User(username=username, email=email, password=hashed_password,location = location, position = position ,full_name= full_name)
        
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!','success')
        return redirect(url_for('login'))       
    return render_template('admin/authentification/register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'photo' in request.files:
            photo = request.files['photo']
            if photo.filename != '':
                filename = secure_filename(photo.filename)
                username = current_user.username
                filename = f"{username}_profile.png"  # Renommer le fichier avec le nom d'utilisateur
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                photo.save(filepath)
                current_user.profile_photo = filename  # Enregistrer uniquement le nom de fichier dans la base de données
                db.session.commit()
                flash('Profile photo updated successfully.')
                return render_template('profile.html', profile_photo=filename)

    # Vérifier si l'utilisateur a déjà une photo de profil enregistrée
    profile_photo = current_user.profile_photo
    if profile_photo is None:
        profile_photo = ""  # Assurez-vous que profile_photo est une chaîne vide s'il n'y a pas de photo de profil

    return render_template('profile.html', profile_photo=profile_photo)


# Route pour changer de mot de passe
@app.route('/change_password', methods=['GET', 'POST'])
@login_required 
def change_password():
    if request.method == 'POST':
        username = request.form['username']
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        # Vérifie si l'utilisateur existe et que l'ancien mot de passe est correct
        user = User.query.filter_by(username=username, password=old_password).first()
        if user:
            user.password = new_password
            db.session.commit()
            flash('Password changed successfully!','success')
            return redirect(url_for('login'))
        else:
            flash('Incorrect username or old password!','error')
    return render_template('admin/authentification/change_password.html')


 


# CRUD User
@app.route('/users')
@role_required('admin','Specialist')
def list_users():
    users = User.query.all()
    log_action(current_user.id, current_user.username, 'list users')
    return render_template('admin/user/list_users.html', users =users , user=user_accessed)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required 
@role_required('admin','Specialist')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        location = request.form['location']
        position = request.form['position']
        full_name = request.form['full_name']  
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, position=  position, email=email, password=hashed_password, location=location, full_name=full_name)
        db.session.add(new_user)
        db.session.commit()
        log_action(current_user.id, current_user.username, 'User added')
        flash('User added successfully!','success')
        return redirect(url_for('list_users'))
    return render_template('admin/user/add_user.html' , user=user_accessed )

@app.route('/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required 
@role_required('admin')
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.full_name = request.form['username']
        user.location = request.form['username']
        user.position= request.form['username']
        user.username = request.form['username']
        user.email = request.form['email']
        user.password = generate_password_hash(request.form['password'])
        db.session.commit()
        log_action(current_user.id, current_user.username, 'User Edited')
        flash('User updated successfully!','success')
        return redirect(url_for('list_users'))
    return render_template('admin/user/edit_user.html', user=user)

@app.route('/users/delete/<int:id>', methods=['POST'])
@login_required 
@role_required('admin')
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    log_action(current_user.id, current_user.username, 'User deleted')
    flash('User deleted successfully!','success')
    return redirect(url_for('list_users'))

# CRUD ROLES FOR SYSTEMS
@app.route('/roles')
@login_required 
@role_required('admin','Specialist')
def list_roles():
    roles = Role.query.all()
    log_action(current_user.id, current_user.username, 'Roles list')
    return render_template('admin/roles/list_roles.html', roles=roles , user=user_accessed)

@app.route('/roles/add', methods=['GET', 'POST'])
@login_required 
@role_required('admin','Specialist')
def add_role():
    if request.method == 'POST':
        name = request.form['name']
        new_role = Role(name=name)
        db.session.add(new_role)
        db.session.commit()
        log_action(current_user.id, current_user.username, 'Role added')
        flash('Role added successfully!','success')
        return redirect(url_for('list_roles'))
    return render_template('admin/roles/add_role.html' , user=user_accessed)

@app.route('/roles/edit/<int:id>', methods=['GET', 'POST'])
@login_required 
@role_required('admin')
def edit_role(id):
    role = Role.query.get_or_404(id)
    if request.method == 'POST':
        role.name = request.form['name']
        db.session.commit()
        log_action(current_user.id, current_user.username, 'Role edited')
        flash('Role updated successfully!','success')
        return redirect(url_for('list_roles'))
    return render_template('admin/roles/edit_role.html', role=role , user=user_accessed)

@app.route('/roles/delete/<int:id>', methods=['POST'])
@login_required 
@role_required('admin')
def delete_role(id):
    role = Role.query.get_or_404(id)
    db.session.delete(role)
    db.session.commit()
    log_action(current_user.id, current_user.username, 'Role deleted')
    flash('Role deleted successfully!')
    return redirect(url_for('list_roles'))


# ASSIGN ROLES TO USERS
@app.route('/users/assign_role/<int:user_id>', methods=['GET', 'POST'])
@login_required 
@role_required('admin')
def assign_role(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()
    if request.method == 'POST':
        selected_roles = request.form.getlist('roles')
        user.roles = Role.query.filter(Role.id.in_(selected_roles)).all()
        db.session.commit()
        log_action(current_user.id, current_user.username, 'Role assignment')
        flash('Roles assigned successfully!','success')
        return redirect(url_for('list_users'))
    return render_template('admin/roles/assign_role.html', user=user, roles=roles)

@app.route('/users/edit_roles/<int:user_id>', methods=['GET', 'POST'])
@login_required 
@role_required('admin')
def edit_roles(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()
    if request.method == 'POST':
        selected_roles = request.form.getlist('roles')
        user.roles = Role.query.filter(Role.id.in_(selected_roles)).all()
        db.session.commit()
        log_action(current_user.id, current_user.username, 'Role edited')
        flash('User roles updated successfully!', 'success')
        return redirect(url_for('list_users'))
    return render_template('admin/edit_user_roles.html', user=user, roles=roles)

@app.route('/users/remove_role/<int:user_id>', methods=['GET', 'POST'])
@login_required 
@role_required('admin')
def remove_role(user_id):
    if request.method == 'POST':
        user = User.query.get_or_404(user_id)
        selected_roles = request.form.getlist('roles')
        user.roles = [role for role in user.roles if str(role.id) not in selected_roles]
        db.session.commit()
        log_action(current_user.id, current_user.username, 'Role deleted')
        flash('Role removed successfully!','success')
        return redirect(url_for('list_users'))
    else:
        user = User.query.get_or_404(user_id)
        return render_template('admin/roles/remove_role.html', user=user)
    



# Start of challenge Seed Quality Management Systems for Soya Plants
def generate_unique_code():
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
        
        if  TruckSample.query.filter_by(entry_code=code).first() is None:
            return code
        elif code not in TruckSample.query.filter_by(entry_code=code).first():
            return code

@app.route('/trucksamples', methods=['GET'])
def get_truck_samples():
    truck_samples = TruckSample.query.all()
    log_action(current_user.id, current_user.username, 'truck samples visited')
    return render_template('trucksamples/trucksamples.html', truck_samples=truck_samples , user=user_accessed)

@app.route('/trucksamples/<int:id>', methods=['GET'])
def get_truck_sample(id):
    truck_sample = TruckSample.query.get_or_404(id)
    log_action(current_user.id, current_user.username, 'Unique views detail truck sample')
    return render_template('trucksamples/trucksample.html', truck_sample=truck_sample , user=user_accessed)

@app.route('/trucksamples/create', methods=['GET', 'POST'])
@role_required('Sampler')
def create_truck_sample():
    if request.method == 'POST':
        # Generate entry code
        in_date = datetime.now().strftime("%Y-%m-%d")
        in_time = datetime.now().strftime("%H:%M")
        truck_number = request.form['truck_number']
        driver_full_name = request.form['driver_full_name']
        driver_phone_number = request.form['driver_phone_number']
        variety = request.form['variety']
        seed_origin = request.form['seed_origin']
        sample_type = request.form['sample_type']
        unloading_location = request.form['unloading_location']
        bags_received = request.form['bags_received']
        bags_rejected = request.form['bags_rejected']

        # Vérification des données
        if not validate_full_name(driver_full_name):
            flash('Invalid driver full name!', 'error')
            return redirect(request.url)
        if not validate_phone_number(driver_phone_number):
            flash('Invalid driver phone number!', 'error')
            return redirect(request.url)
        if not validate_truck_number(truck_number):
            flash('Invalid truck number!', 'error')
            return redirect(request.url)
        
        if seed_origin == 'other':
            seed_origin = request.form['other_origin']

        if unloading_location == 'otherlocation':
            unloading_location = request.form['otherlocation']
            if unloading_location=='externallo':
                unloading_location= request.form['external']

        if sample_type=='ps':
            bags_received is None
            bags_rejected is None   
                 
        return render_template('trucksamples/confirm_trucksample_creation.html',
                                   in_date=in_date,
                                   in_time=in_time,
                                   entry_code = generate_unique_code(),
                                   truck_number=truck_number,
                                   driver_full_name=driver_full_name,
                                   driver_phone_number=driver_phone_number,
                                   variety=variety,
                                   seed_origin=seed_origin,
                                   sample_type=sample_type,
                                   unloading_location=unloading_location,
                                   bags_received=bags_received,
                                   bags_rejected=bags_rejected)
        
    return render_template('trucksamples/create_trucksample.html' , user=user_accessed)

 


@app.route('/confirm_trucksample_creation', methods=['POST'])
@role_required('Sampler')
def confirm_trucksample_creation():
    if request.method == 'POST':
        entry_code = request.form['entry_code']        
        confirm_choice = request.form.get('confirm', 'no')  # If 'confirm' key is not present, default to 'no'
        if confirm_choice == 'yes':
            # Retrieve form data
            new_truck_sample = TruckSample(
                in_date = datetime.now().strftime("%Y-%m-%d"),
                in_time = datetime.now().strftime("%H:%M"),
                entry_code = entry_code,
                truck_number = request.form['truck_number'],
                driver_name = request.form['driver_full_name'],
                driver_phone_number = request.form['driver_phone_number'],
                variety = request.form['variety'],
                seed_origin = request.form['seed_origin'],
                sample_type = request.form['sample_type'],
                unloading_location = request.form['unloading_location'],
                bags_received = request.form['bags_received'],
                bags_rejected = request.form['bags_rejected'],
            )

            # Add the new sample to the database and commit changes
            db.session.add(new_truck_sample)
            db.session.commit()

            # Log the action and display a success message
            log_action(current_user.id, current_user.username, 'Truck sample created', entry_code)
            flash('Truck sample created successfully', 'success')
        else:
            # If user cancels, log the action and display a cancellation message
            log_action(current_user.id, current_user.username, 'Cancelled confirmation for truck sample creation')
            flash('Truck sample creation cancelled.', 'info')

        # Redirect user to the home page
        return redirect(url_for('home'))

    # If HTTP method is not POST, also redirect the user to the home page
    return redirect(url_for('home'))




@app.route('/trucksamples/<int:id>/edit', methods=['GET', 'POST'])
@role_required('Analyst','Supervisor','Coordinator','Inspector')
def edit_truck_sample(id):
    truck_sample = TruckSample.query.get_or_404(id)
    if request.method == 'POST':
        truck_sample.truck_number = request.form['truck_number']
        truck_sample.driver_name = request.form['driver_name']
        truck_sample.driver_phone_number = request.form['driver_phone_number']
        truck_sample.variety = request.form['variety']
        truck_sample.seed_origin = request.form['seed_origin']
        truck_sample.sample_type = request.form['sample_type']
        truck_sample.unloading_location = request.form['unloading_location']
        truck_sample.bags_received = request.form['bags_received']
        truck_sample.bags_rejected = request.form['bags_rejected']
        db.session.commit()
        entry_code = truck_sample.entry_code
        log_action(current_user.id, current_user.username, 'Truck sample edited successfully', entry_code)
        flash('truck_sample edited successfully', 'success')
        return redirect(url_for('home'))
    return render_template('trucksamples/edit_trucksample.html', truck_sample=truck_sample)

@app.route('/trucksamples/<int:id>/delete', methods=['POST'])
@role_required('admin')
def delete_truck_sample(id):
    truck_sample = TruckSample.query.get_or_404(id)
    entry_code = truck_sample.entry_code
    db.session.delete(truck_sample)
    db.session.commit()
    log_action(current_user.id, current_user.username, 'Truck Sample Deleted', entry_code)
    flash('Truck Sample Deleted', 'success')
    return redirect(url_for('home'))

 
# Route pour les analyses peripheral samples

@app.route('/entry_code_peripheral', methods=['GET', 'POST'])
@role_required('Analyst','Supervisor','Coordinator','Inspector')

def check_entry_code_peripheral():
    if request.method == 'POST':
        entry_code = request.form['entry_code']
        truck = TruckSample.query.filter_by(entry_code=entry_code).first()
        Peripheralsample = PeripheralSample.query.filter_by(truck_entry_code=entry_code).first()

        if truck and (Peripheralsample is None):
            log_action(current_user.id, current_user.username, 'visited analysis peripheral entry_code')
            return redirect(url_for('analyze_peripheral_sample', entry_code=entry_code))
        elif truck and Peripheralsample:
            log_action(current_user.id, current_user.username, 'Peripheral entry_code already  used')
            flash('Peripheral entry_code already  used', 'danger')
            return redirect(url_for('home'))
        else:
            log_action(current_user.id, current_user.username, 'wrong entry code for peripheral checkpoint')
            flash('Entry Code invalide, veuillez réessayer.', 'danger')
            return redirect(url_for('home'))
    return render_template('entry_code.html' , user = user_accessed)


#verification pour peripheral sample en me basant sur sample type  sample_type

@app.route('/truck/<entry_code>/peripheral_analyze', methods=['GET', 'POST'])
@role_required('Analyst','Supervisor','Coordinator','Inspector')
def analyze_peripheral_sample(entry_code):
    entry_code = entry_code
    truck = TruckSample.query.filter_by(entry_code=entry_code).first_or_404()
    
    Peripheralsample = PeripheralSample.query.filter_by(truck_entry_code=entry_code).first()
    if truck.sample_type=='ps' and Peripheralsample is None:
        if request.method == 'POST':
            humidity_percent = request.form['humidity_percent']
            ofm_g = request.form['ofm_g']
            damage_g = request.form['damage_g']

            # Valider les donnéesx                                  
            if not all(validate_number(value) for value in [humidity_percent, ofm_g, damage_g]):
                log_action(current_user.id, current_user.username, 'Wrong peripheral result')
                flash('Veuillez saisir des valeurs numériques valides.', 'error')
                return redirect(url_for('check_entry_code_peripheral'))

            # Convertir les valeurs en float
            humidity_percent = float(humidity_percent)
            ofm_g = float(ofm_g)
            damage_g = float(damage_g)

        # Calculer les pourcentages
            ofm_percent = round((ofm_g / 500) * 100, 2)
            damage_percent = round((damage_g / 500) * 100, 2)
            log_action(current_user.id, current_user.username, 'Peripheral Result good')
            return render_template('peripheralsample/confirm_peripheral_test.html', truck=truck, ofm_g=ofm_g, damage_g=damage_g, humidity_percent=humidity_percent, ofm_percent=ofm_percent, damage_percent=damage_percent , user = user_accessed,  entry_code = entry_code)
    return render_template('peripheralsample/analyze_peripheral_sample.html', truck=truck  , user = user_accessed)

@app.route('/confirm_peripheral_results', methods=['POST'])
def confirm_peripheral_results():
    entry_code = request.form['entry_code']
    if request.form['confirm'] == 'yes':
        analysis = PeripheralSample(
            humidity_percent=request.form['humidity_percent'],
            truck_entry_code=request.form['entry_code'],
            ofm_g=request.form['ofm_g'],
            damage_g=request.form['damage_g'],
            ofm_percent=request.form['ofm_percent'],
            damage_percent=request.form['damage_percent'],
            in_date = datetime.now().strftime("%Y-%m-%d"),
            in_time = datetime.now().strftime("%H:%M")

        )
        
        log_action(current_user.id, current_user.username, 'Confirm peripheral good', entry_code)
        
        db.session.add(analysis)
        db.session.commit()
        flash('Les données d\'analyse ont été enregistrées avec succès.', 'success')
    else:
        log_action(current_user.id, current_user.username, 'Not Conform peripheral good')
        flash('L\'enregistrement des données d\'analyse a été annulé.', 'info')
    return redirect(url_for('home'))

 
def generate_sample_code(unloading_location):
    # Récupérer le dernier échantillon pour l'emplacement de déchargement spécifié
    last_sample_code = db.session.query(MasterSample).join(
        TruckSample,
        MasterSample.truck_entry_code == TruckSample.entry_code
    ).filter(
        TruckSample.unloading_location == unloading_location
    ).order_by(
        MasterSample.sample_code.desc()
    ).first()
    if not last_sample_code:
        # Aucun échantillon enregistré pour cet emplacement, commencer à partir de A1
        if unloading_location in ['BO', 'BAB']:
            return f"SC{unloading_location}-A1"
        elif unloading_location in ['WH{:02d}'.format(i) for i in range(1, 29)]:
            return f"SCSDP-{unloading_location}-A1"
    else:
        # Extraire le numéro de
        #  séquence de l'échantillon précédent
        last_sequence_number = int(last_sample_code.sample_code.split('-')[-1][1:])
        next_sequence_number = last_sequence_number + 1
        
        # Générer le nouveau code d'échantillon en fonction de l'emplacement de déchargement
        if unloading_location in ['BO', 'BAB']:
            return f"SC{unloading_location}-A{next_sequence_number}"
        elif unloading_location in ['WH{:02d}'.format(i) for i in range(1, 29)]:
            return f"SCSDP-{unloading_location}-A{next_sequence_number}"


@app.route('/entry_code_master', methods=['GET', 'POST'])
@role_required('Analyst','Supervisor','Coordinator','Inspector')

def check_entry_code_master():
    if request.method == 'POST':
        entry_code = request.form['entry_code']
        truck = TruckSample.query.filter_by(entry_code=entry_code).first()
        mastersample =MasterSample.query.filter_by(truck_entry_code=entry_code).first()
        if truck and (mastersample is None):
            log_action(current_user.id, current_user.username, 'Visited analysis master')
            return redirect(url_for('analyze_master_sample', entry_code=entry_code))
        
        elif truck and (mastersample is not None):
            log_action(current_user.id, current_user.username, 'Entry Code alrealy used for this master sample')
            flash('Entry already used', 'danger')
            return redirect(url_for('home'))
        else:
            log_action(current_user.id, current_user.username, 'Wrong entry code for master')
            flash('Entry Code invalide, Try it again.', 'danger')
            return redirect(url_for('home'))
    return render_template('entry_code.html' , user = user_accessed)


# Fonction npour verifier si la colonne de sample type est okay. Si
@app.route('/truck/<entry_code>/master_analyze', methods=['GET', 'POST'])
@role_required('Analyst','Supervisor','Coordinator','Inspector')

def analyze_master_sample(entry_code):
    truck = TruckSample.query.filter_by(entry_code=entry_code).first_or_404()
    unloading_location = truck.unloading_location
    first_decision = FirstDecision.query.filter_by(truck_entry_code=entry_code).first()   
    mastersample =MasterSample.query.filter_by(truck_entry_code=entry_code).first()
 
    if (truck.sample_type =='ms' or (truck.sample_type =='ps' and first_decision is not None and first_decision.decision_first in ['accepted', 'approved'])) and (mastersample is None):
        if request.method == 'POST':
            humidity_percent = request.form['humidity_percent']
            green_seed_g = request.form['green_seed_g']
            small_seed_g = request.form['small_seed_g']
            split_g = request.form['split_g']
            ofm_g = request.form['ofm_g']
            damage_g = request.form['damage_g']

            # Valider les donnéesx                                  
            if not all(validate_number(value) for value in [humidity_percent, green_seed_g, small_seed_g, split_g, ofm_g, damage_g]):
                log_action(current_user.id, current_user.username, 'Wrong master data in')
                flash('Veuillez saisir des valeurs numériques valides.', 'error')
                return redirect(url_for('check_entry_code_master'))

            # Convertir les valeurs en float
            humidity_percent = float(humidity_percent)
            green_seed_g = float(green_seed_g)
            small_seed_g = float(small_seed_g)
            split_g = float(split_g)
            ofm_g = float(ofm_g)
            damage_g = float(damage_g)
            sample_code = generate_sample_code(unloading_location)

        # Calculer les pourcentages
            green_seed_percent = round((green_seed_g / 500) * 100, 2)
            small_seed_percent = round((small_seed_g / 500) * 100, 2)
            split_percent = round((split_g / 500) * 100, 2)
            ofm_percent = round((ofm_g / 500) * 100, 2)
            damage_percent = round((damage_g / 500) * 100, 2)
            log_action(current_user.id, current_user.username, 'Good master data')
            return render_template('mastersample/confirm_master_test.html', truck=truck, green_seed_g=green_seed_g, small_seed_g=small_seed_g, split_g=split_g, ofm_g=ofm_g, damage_g=damage_g, humidity_percent=humidity_percent, green_seed_percent=green_seed_percent, small_seed_percent=small_seed_percent, split_percent=split_percent, ofm_percent=ofm_percent, damage_percent=damage_percent , user = user_accessed, sample_code = sample_code, entry_code = entry_code)
    return render_template('mastersample/analyze_master_sample.html', truck=truck , user = user_accessed)

@app.route('/confirm_master_results', methods=['POST'])
def confirm_master_results():
    entry_code = request.form['entry_code']
    if request.form['confirm'] == 'yes':
        analysis = MasterSample(
            humidity_percent=request.form['humidity_percent'],
            truck_entry_code=request.form['entry_code'],
            green_seed_g=request.form['green_seed_g'],
            small_seed_g=request.form['small_seed_g'],
            split_g=request.form['split_g'],
            ofm_g=request.form['ofm_g'],
            damage_g=request.form['damage_g'],
            green_seed_percent=request.form['green_seed_percent'],
            small_seed_percent=request.form['small_seed_percent'],
            split_percent=request.form['split_percent'],
            ofm_percent=request.form['ofm_percent'],
            damage_percent=request.form['damage_percent'],
            in_date = datetime.now().strftime("%Y-%m-%d"),
            in_time = datetime.now().strftime("%H:%M"),
            sample_code=request.form['sample_code']
        )
        entry_code = entry_code
        log_action(current_user.id, current_user.username, 'Confirmation master data', entry_code)
        db.session.add(analysis)
        db.session.commit()
        flash('Les données d\'analyse ont été enregistrées avec succès.', 'success')
    else:
        log_action(current_user.id, current_user.username, 'cancelled confirmation')
        flash('L\'enregistrement des données d\'analyse a été annulé.', 'info')
    return redirect(url_for('home'))


# truck sample info
@app.route('/tsbo')
def tsbo():
    log_action(current_user.id, current_user.username, 'Truck sample info')
    results = TruckSample.query.filter_by(unloading_location='BO').all()
    return render_template('trucksamples/tsbo.html',results=results)

@app.route('/tsbowh')
def tsbowh():
    log_action(current_user.id, current_user.username, 'Truck Sample BO WH')
    desired_locations = ['WH02', 'WH08']
    results = TruckSample.query.filter(TruckSample.unloading_location.in_(desired_locations)).all()
    return render_template('trucksamples/tsbowh.html',results=results)

@app.route('/tsbab')
def tsbab():
    log_action(current_user.id, current_user.username, 'Truck Sample BAB')
    results = TruckSample.query.filter_by(unloading_location='BAB').all()
    return render_template('trucksamples/tsbab.html',results=results)

@app.route('/tsbabwh')
def tsbabwh():
    log_action(current_user.id, current_user.username, 'Trucks Sample BAB WH')
    unwanted_locations = ['BAB', 'BO', 'WH02', 'WH08']
    results = TruckSample.query.filter(not_(TruckSample.unloading_location.in_(unwanted_locations))).all()   
    return render_template('trucksamples/tsbabwh.html',results=results)


#peripheral sample
@app.route('/ptbo')
def ptbo():
    log_action(current_user.id, current_user.username, 'Peripheral BO')
    results = db.session.query(TruckSample, PeripheralSample, FirstDecision)\
        .join(PeripheralSample, PeripheralSample.truck_entry_code == TruckSample.entry_code)\
        .outerjoin(FirstDecision, FirstDecision.truck_entry_code == TruckSample.entry_code)\
        .filter(TruckSample.unloading_location == 'BO').all()
    return render_template('peripheralsample/ptbo.html',results=results )

@app.route('/ptbowh')
def ptbowh():
    log_action(current_user.id, current_user.username, 'Peripheral BO WH')
    desired_locations = ['WH02', 'WH08']
    #results = db.session.query(TruckSample, PeripheralSample).join(PeripheralSample, PeripheralSample.truck_entry_code == TruckSample.entry_code)             
    results = db.session.query(TruckSample, PeripheralSample, FirstDecision)\
        .join(PeripheralSample, PeripheralSample.truck_entry_code == TruckSample.entry_code)\
        .outerjoin(FirstDecision, FirstDecision.truck_entry_code == TruckSample.entry_code)\
        .filter(TruckSample.unloading_location.in_(desired_locations)).all()
    return render_template('peripheralsample/ptbowh.html',results=results)

@app.route('/ptbab')
def ptbab():
    log_action(current_user.id, current_user.username, 'peripheral sample BAB')
    results = db.session.query(TruckSample, PeripheralSample, FirstDecision)\
        .join(PeripheralSample, PeripheralSample.truck_entry_code == TruckSample.entry_code)\
        .outerjoin(FirstDecision, FirstDecision.truck_entry_code == TruckSample.entry_code)\
        .filter(TruckSample.unloading_location == 'BAB').all()

    #results = db.session.query(TruckSample, PeripheralSample).join(PeripheralSample, PeripheralSample.truck_entry_code == TruckSample.entry_code).filter(TruckSample.unloading_location == 'BAB').all()
    return render_template('peripheralsample/ptbab.html',results=results)

@app.route('/ptbabwh')
def ptbabwh():
    log_action(current_user.id, current_user.username, 'peripheral bab wh')
    unwanted_locations = ['BAB', 'BO', 'WH02', 'WH08']
    results = db.session.query(TruckSample, PeripheralSample, FirstDecision)\
        .join(PeripheralSample, PeripheralSample.truck_entry_code == TruckSample.entry_code)\
        .outerjoin(FirstDecision, FirstDecision.truck_entry_code == TruckSample.entry_code)\
        .filter(not_(TruckSample.unloading_location.in_(unwanted_locations))).all() 
    #results = db.session.query(TruckSample, PeripheralSample).join(PeripheralSample, PeripheralSample.truck_entry_code == TruckSample.entry_code).filter(not_(TruckSample.unloading_location.in_(unwanted_locations))).all()   
    return render_template('peripheralsample/ptbabwh.html',results=results)


@app.route('/msbo')
def msbo():
    log_action(current_user.id, current_user.username, 'master bo')
    results = db.session.query(TruckSample, MasterSample, FinalDecision)\
        .join(MasterSample, MasterSample.truck_entry_code == TruckSample.entry_code)\
        .outerjoin(FinalDecision, FinalDecision.truck_entry_code == TruckSample.entry_code)\
        .filter(TruckSample.unloading_location == 'BO').all()
    
    return render_template('mastersample/msbo.html',results=results)
@app.route('/msbowh')
def msbowh():
    log_action(current_user.id, current_user.username, 'master bo wh')
    desired_locations = ['WH02', 'WH08']
    results = db.session.query(TruckSample, MasterSample, FinalDecision)\
        .join(MasterSample, MasterSample.truck_entry_code == TruckSample.entry_code)\
        .outerjoin(FinalDecision, FinalDecision.truck_entry_code == TruckSample.entry_code)\
        .filter(TruckSample.unloading_location.in_(desired_locations)).all()
    return render_template('mastersample/msbowh.html',results=results)

@app.route('/msbab')
def msbab():
    log_action(current_user.id, current_user.username, 'master bab')
    results = db.session.query(TruckSample, MasterSample, FinalDecision)\
        .join(MasterSample, MasterSample.truck_entry_code == TruckSample.entry_code)\
        .outerjoin(FinalDecision, FinalDecision.truck_entry_code == TruckSample.entry_code)\
        .filter(TruckSample.unloading_location == 'BAB').all()
    return render_template('mastersample/msbab.html',results=results)

@app.route('/msbabwh')
def msbabwh():
    log_action(current_user.id, current_user.username, 'Role added')
    unwanted_locations = ['BAB', 'BO', 'WH02', 'WH08']
    results = db.session.query(TruckSample, MasterSample, FinalDecision)\
        .join(MasterSample, MasterSample.truck_entry_code == TruckSample.entry_code)\
        .outerjoin(FinalDecision, FinalDecision.truck_entry_code == TruckSample.entry_code)\
        .filter(not_(TruckSample.unloading_location.in_(unwanted_locations))).all()   
    return render_template('mastersample/msbabwh.html',results=results)


@app.route('/create_first_decision/<truck_entry_code>', methods=['GET', 'POST'])
@role_required('Manager','Supervisor','Coordinator','Inspector')

def create_first_decision(truck_entry_code):
    if request.method == 'POST':
        decision_first = request.form['decision_first']
        reason_first = request.form['reason_first']
        
        truck_sample = TruckSample.query.filter_by(entry_code=truck_entry_code).first()
        first_decision = FirstDecision.query.filter_by(truck_entry_code=truck_entry_code).first()
        if truck_sample and (first_decision is None):
            first_decision = FirstDecision(
                in_date_first=datetime.now().strftime("%Y-%m-%d"),
                in_time_first=datetime.now().strftime("%H:%M"),
                truck_entry_code=truck_entry_code,
                decision_first=decision_first,
                reason_first=reason_first
            )
            db.session.add(first_decision)
            db.session.commit()
            entry_code = truck_sample.entry_code
            log_action(current_user.id, current_user.username, 'ok first decision', entry_code)
            flash('First decision recorded successfully!', 'success')
            return redirect(url_for('home'))
        else:
            log_action(current_user.id, current_user.username, 'RNo decison ')
            flash('Truck sample not found.', 'danger')
            return redirect(url_for('error'))
    return render_template('/decison/create_first_decision.html', truck_entry_code=truck_entry_code)

@app.route('/create_final_decision/<truck_entry_code>', methods=['GET', 'POST'])
@role_required('Manager','Supervisor','Coordinator','Inspector')

def create_final_decision(truck_entry_code):
    if request.method == 'POST':
        decision_final = request.form['decision_final']
        reason_final = request.form['reason_final']
        
        truck_sample = TruckSample.query.filter_by(entry_code=truck_entry_code).first()
        final_decision = FinalDecision.query.filter_by(truck_entry_code=truck_entry_code).first()
        if truck_sample and (final_decision is None):
            final_decision = FinalDecision(
                truck_entry_code=truck_entry_code,
                in_date_final=datetime.now().strftime("%Y-%m-%d"),
                in_time_final=datetime.now().strftime("%H:%M"),
                decision_final=decision_final,
                reason_final=reason_final
            )
            db.session.add(final_decision)
            db.session.commit()
            entry_code = truck_sample.entry_code
            log_action(current_user.id, current_user.username, 'final decision', entry_code)
            flash('Final decision created successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Truck sample not found.', 'danger')
            return redirect(url_for('error'))
    return render_template('decison/create_final_decision.html', truck_entry_code=truck_entry_code)




def get_log_actions_for_entry_code(entry_code):
    log_actions = LogAction.query.filter_by(entry_code=entry_code).all()
    return log_actions


def get_truck_entry_info(truck_entry_code):
    # Récupérer les informations de TruckSample
    truck_sample = TruckSample.query.filter_by(entry_code=truck_entry_code).first()
    if truck_sample is None:
        return None  # Aucune entrée trouvée pour le code d'entrée du camion
    
    # Récupérer les informations de PeripheralSample
    peripheral_sample = PeripheralSample.query.filter_by(truck_entry_code=truck_entry_code).first()
    
    # Récupérer les informations de MasterSample
    master_sample = MasterSample.query.filter_by(truck_entry_code=truck_entry_code).first()
    
    # Récupérer les informations de FirstDecision
    first_decision = FirstDecision.query.filter_by(truck_entry_code=truck_entry_code).first()
    
    # Récupérer les informations de FinalDecision
    final_decision = FinalDecision.query.filter_by(truck_entry_code=truck_entry_code).first()
    
    # Créer un dictionnaire pour stocker toutes les informations
    truck_entry_info = {
        "TruckSample": truck_sample,
        "PeripheralSample": peripheral_sample,
        "MasterSample": master_sample,
        "FirstDecision": first_decision,
        "FinalDecision": final_decision,
     }
    
    return truck_entry_info  


@app.route('/analysis_results', methods=['GET', 'POST'])
@role_required('Analyst','Supervisor','Coordinator','Inspector','admin')

def check_analysis_results():
    if request.method == 'POST':
        entry_code = request.form['entry_code']
        truck = TruckSample.query.filter_by(entry_code=entry_code).first()
        
        if truck:
            log_action(current_user.id, current_user.username, 'Visited analysis results')
            return redirect(url_for('show_truck_entry_info', truck_entry_code=entry_code))
        else:
            log_action(current_user.id, current_user.username, 'Wrong entry code for analysis results')
            flash('Invalid Entry Code, Try it again.', 'danger')
            return redirect(url_for('home'))
    return render_template('entry_code.html' , user = user_accessed)


@app.route('/truck_entry/<truck_entry_code>')
@role_required('Analyst','Supervisor','Coordinator','Inspector','admin')

def show_truck_entry_info(truck_entry_code):
    # Récupérer les informations du camion
    truck_entry_info = get_truck_entry_info(truck_entry_code)
    log_actions = get_log_actions_for_entry_code(truck_entry_code)
    # Vérifier si les données existent pour chaque table et afficher "DATA NOT READY" si elles ne sont pas disponibles
    for table_name, entry in truck_entry_info.items():
        if entry is None:
            truck_entry_info[table_name] = "DATA NOT READY"

    # Rendre le modèle de template avec les données récupérées
    return render_template('truck_entry_info.html', truck_entry_info=truck_entry_info ,log_actions = log_actions )



from io import BytesIO
 
from flask import make_response
from datetime import datetime

@app.route('/export_excel')

@role_required('admin')

def export_data_to_excel():
    # Récupérer toutes les données des tables
    log_actions = LogAction.query.all()
    truck_samples = TruckSample.query.all()
    peripheral_samples = PeripheralSample.query.all()
    master_samples = MasterSample.query.all()
    first_decisions = FirstDecision.query.all()
    final_decisions = FinalDecision.query.all()

    # Créer des DataFrames à partir des données
    log_actions_df = pd.DataFrame([(log_action.id, log_action.user_id, log_action.username, log_action.time, log_action.action, log_action.entry_code) for log_action in log_actions], 
                                   columns=["ID", "User ID", "Username", "Time", "Action", "Entry Code"])
    truck_samples_df = pd.DataFrame([(truck_sample.id, truck_sample.in_date, truck_sample.in_time, truck_sample.entry_code,
                                      truck_sample.truck_number, truck_sample.driver_name, truck_sample.driver_phone_number,
                                      truck_sample.variety, truck_sample.seed_origin, truck_sample.sample_type,
                                      truck_sample.unloading_location, truck_sample.bags_received, truck_sample.bags_rejected) for truck_sample in truck_samples], 
                                    columns=["ID", "In Date", "In Time", "Entry Code", "Truck Number", "Driver Name", "Driver Phone Number",
                                             "Variety", "Seed Origin", "Sample Type", "Unloading Location", "Bags Received", "Bags Rejected"])
    peripheral_samples_df = pd.DataFrame([(peripheral_sample.id, peripheral_sample.in_date, peripheral_sample.in_time,
                                           peripheral_sample.truck_entry_code, peripheral_sample.damage_g, peripheral_sample.ofm_g,
                                           peripheral_sample.humidity_percent, peripheral_sample.damage_percent, peripheral_sample.ofm_percent) for peripheral_sample in peripheral_samples], 
                                         columns=["ID", "In Date", "In Time", "Truck Entry Code", "Damage (g)", "OFM (g)", "Humidity (%)",
                                                  "Damage (%)", "OFM (%)"])
    master_samples_df = pd.DataFrame([(master_sample.id, master_sample.in_date, master_sample.in_time, master_sample.truck_entry_code,
                                       master_sample.damage_g, master_sample.ofm_g, master_sample.green_seed_g,
                                       master_sample.small_seed_g, master_sample.split_g, master_sample.humidity_percent,
                                       master_sample.green_seed_percent, master_sample.small_seed_percent,
                                       master_sample.split_percent, master_sample.damage_percent, master_sample.ofm_percent,
                                       master_sample.sample_code) for master_sample in master_samples], 
                                     columns=["ID", "In Date", "In Time", "Truck Entry Code", "Damage (g)", "OFM (g)", "Green Seed (g)",
                                              "Small Seed (g)", "Split (g)", "Humidity (%)", "Green Seed (%)", "Small Seed (%)",
                                              "Split (%)", "Damage (%)", "OFM (%)", "Sample Code"])
    first_decisions_df = pd.DataFrame([(first_decision.id, first_decision.in_date_first, first_decision.in_time_first,
                                        first_decision.truck_entry_code, first_decision.decision_first, first_decision.reason_first) for first_decision in first_decisions], 
                                      columns=["ID", "In Date First", "In Time First", "Truck Entry Code", "Decision First", "Reason First"])
    final_decisions_df = pd.DataFrame([(final_decision.id, final_decision.truck_entry_code, final_decision.in_date_final,
                                        final_decision.in_time_final, final_decision.decision_final, final_decision.reason_final) for final_decision in final_decisions], 
                                      columns=["ID", "Truck Entry Code", "In Date Final", "In Time Final", "Decision Final", "Reason Final"])

    # Créer un objet BytesIO pour stocker le fichier Excel en mémoire
    excel_file = BytesIO()

    # Créer un écrivain Excel
    with pd.ExcelWriter(excel_file, engine="xlsxwriter") as writer:
        # Ajouter chaque DataFrame dans une feuille Excel distincte
        log_actions_df.to_excel(writer, index=False, sheet_name="Log Actions")
        truck_samples_df.to_excel(writer, index=False, sheet_name="Truck Samples")
        peripheral_samples_df.to_excel(writer, index=False, sheet_name="Peripheral Samples")
        master_samples_df.to_excel(writer, index=False, sheet_name="Master Samples")
        first_decisions_df.to_excel(writer, index=False, sheet_name="First Decisions")
        final_decisions_df.to_excel(writer, index=False, sheet_name="Final Decisions")

    # Revenir au début du fichier BytesIO
    excel_file.seek(0)

    # Créer une réponse HTTP avec le contenu du fichier Excel en mémoire
    response = make_response(excel_file.getvalue())

    # Définir le nom de fichier avec la date actuelle
    current_date = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    filename = f"Today_report{current_date}.xlsx"
    
    # Définir les en-têtes de la réponse
    response.headers['Content-Disposition'] = f'attachment; filename={filename}'
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

    return response

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
