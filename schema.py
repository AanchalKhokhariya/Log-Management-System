import graphene
from models import User, Log, db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


class UserType(graphene.ObjectType):
    id = graphene.Int()
    name = graphene.String()
    gmail = graphene.String()
    role = graphene.Int()


class LogType(graphene.ObjectType):
    id = graphene.Int()
    user_id = graphene.Int()
    date = graphene.String()
    check_in = graphene.String()
    check_out = graphene.String()
    task = graphene.String()
    total_hours = graphene.Float()

    def resolve_date(parent, info):
        return str(parent.date)

    def resolve_check_in(parent, info):
        return str(parent.check_in)

    def resolve_check_out(parent, info):
        return str(parent.check_out)



class Query(graphene.ObjectType):
    all_users = graphene.List(UserType)
    all_logs = graphene.List(LogType)
    user_logs = graphene.List(LogType, user_id=graphene.Int())

    def resolve_all_users(parent, info):
        return User.query.all()

    def resolve_all_logs(parent, info):
        return Log.query.all()

    def resolve_user_logs(parent, info, user_id):
        return Log.query.filter_by(user_id=user_id).all()


class RegisterUser(graphene.Mutation):
    class Arguments:
        name = graphene.String(required=True)
        gmail = graphene.String(required=True)
        password = graphene.String(required=True)
        role = graphene.Int(required=True)

    user = graphene.Field(UserType)
    message = graphene.String()

    def mutate(self, info, name, gmail, password, role):
       
        if User.query.filter((User.name == name) | (User.gmail == gmail)).first():
            return RegisterUser(message="User already exists")

        user = User(
            name=name,
            gmail=gmail,
            password=generate_password_hash(password),
            role=role
        )

        db.session.add(user)
        db.session.commit()

        return RegisterUser(user=user, message="User created successfully")



class LoginUser(graphene.Mutation):
    class Arguments:
        gmail = graphene.String(required=True)
        password = graphene.String(required=True)

    message = graphene.String()
    user = graphene.Field(UserType)

    def mutate(self, info, gmail, password):
        user = User.query.filter_by(gmail=gmail).first()

        if not user or not check_password_hash(user.password, password):
            return LoginUser(message="Invalid credentials")

        return LoginUser(user=user, message="Login successful")



class AddLog(graphene.Mutation):
    class Arguments:
        user_id = graphene.Int(required=True)
        date = graphene.String(required=True)
        check_in = graphene.String(required=True)
        check_out = graphene.String(required=True)
        task = graphene.String(required=True)

    log = graphene.Field(LogType)
    message = graphene.String()

    def mutate(self, info, user_id, date, check_in, check_out, task):
        try:
            log_date = datetime.strptime(date, "%Y-%m-%d").date()
            t1 = datetime.strptime(check_in, "%H:%M")
            t2 = datetime.strptime(check_out, "%H:%M")

            total_hours = round((t2 - t1).total_seconds() / 3600, 2)

            if total_hours < 0:
                return AddLog(message="Invalid time range")

            log = Log(
                user_id=user_id,
                date=log_date,
                check_in=t1.time(),
                check_out=t2.time(),
                task=task,
                total_hours=total_hours
            )

            db.session.add(log)
            db.session.commit()

            return AddLog(log=log, message="Log added successfully")

        except Exception as e:
            return AddLog(message="Error adding log")



class DeleteLog(graphene.Mutation):
    class Arguments:
        log_id = graphene.Int(required=True)

    message = graphene.String()

    def mutate(self, info, log_id):
        log = Log.query.get(log_id)

        if not log:
            return DeleteLog(message="Log not found")

        db.session.delete(log)
        db.session.commit()

        return DeleteLog(message="Log deleted successfully")



class Mutation(graphene.ObjectType):
    register_user = RegisterUser.Field()
    login_user = LoginUser.Field()
    add_log = AddLog.Field()
    delete_log = DeleteLog.Field()



schema = graphene.Schema(query=Query, mutation=Mutation)