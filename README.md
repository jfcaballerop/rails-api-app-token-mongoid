# README

Aplicacion base para crearte una API Backend en Rails 5, con MongoDB y protegida por Token.

Manual adaptado del siguiente [ link ](https://www.pluralsight.com/guides/token-based-authentication-with-ruby-on-rails-5-api)

## Conceptos
------

* ¿Qué contiene un token JWT? 

El token está separado en tres valores separados por puntos codificados en base 64, cada uno representando un tipo diferente de datos: 
- HEADER: Consigna del tipo de token (JWT) y el tipo de algoritmo de cifrado (HS256) codificado en base-64. 
- PAYLOAD: contiene información sobre el usuario y su función. Por ejemplo, la carga del token puede contener el correo electrónico y la contraseña. 
- SIGNATURE: Signature es una clave única que identifica el servicio que crea el encabezado. En este caso, la firma del token será una versión codificada en base 64 de la clave secreta de la aplicación Rails (Rails.application.secrets.secret_key_base. Como cada aplicación tiene una clave base única, esta clave secreta sirve como la firma del token.

## Pasos
---------
### 1. Crear la aplicacion
```
rails . new api-app-token-mongoid --api -T

```

### 2. Crear el modelo de usuario
---
```
 rails g model User name email password_digest
 ```

 *se puede cambiar o añadir los campos, por ejemplo añadir el LOGIN*

 El método *has_secure_password* debe agregarse al modelo para asegurarse de que la contraseña esté correctamente encriptada en la base de datos: *has_secure_password* es parte de la gema bcrypt, por lo que debemos instalarla primero. 
 Agrégalo al gemfile:
```
gem 'bcrypt', '~> 3.1.7'
---
bundle install

```
```
#app/models/user.rb

class User < ApplicationRecord
 has_secure_password
end
```
### 3. Codificación y decodificación de tokens JWT
---
```
gem 'jwt'
---
bundle install

```
Una vez que se instala la gema, se puede acceder a través de la variable global JWT

```
# lib/json_web_token.rb

class JsonWebToken
 class << self
   def encode(payload, exp = 24.hours.from_now)
     payload[:exp] = exp.to_i
     JWT.encode(payload, Rails.application.secrets.secret_key_base)
   end

   def decode(token)
     body = JWT.decode(token, Rails.application.secrets.secret_key_base)[0]
     HashWithIndifferentAccess.new body
   rescue
     nil
   end
 end
end
```
Deberemos haber creado antes el fichero:

*api-app-token-mongoid/config/secrets.yml*
```
development:
  secret_key_base: 836fa3665997a860728bcb9e9a1e704d427cfc920e79d847d79c8a9a907b9e965defa4154b2b86bdec6930adbe33f21364523a6f6ce363865724549fdfc08553
test:
  secret_key_base: 5a37811464e7d378488b0f073e2193b093682e4e21f5d6f3ae0a4e1781e61a351fdc878a843424e81c73fb484a40d23f92c8dafac4870e74ede6e5e174423010
production:
  secret_key_base: <%= ENV["SECRET_KEY_BASE"] %>
```
Para asegurarse de que todo funcionará, los contenidos del directorio lib deben incluirse cuando se carga la aplicación Rails:
```
#config/application.rb

module ApiApp
  class Application < Rails::Application
    #.....
    config.autoload_paths << Rails.root.join('lib')
    #.....
    end
   end
```

### 4. Autenticando usuarios
---
En lugar de usar métodos de controlador privados, se puede usar simple_command: simple_command.

La gema de comando simple es una forma fácil de crear servicios. Su función es similar a la función de un ayudante, pero en lugar de facilitar la conexión entre el controlador y la vista, hace lo mismo para el controlador y el modelo. De esta forma, podemos acortar el código en los modelos y controladores.

Agrega la gema a tu Agrega la gema a tu Gemfile:
```
gem 'simple_command'

---

bundle install

```

```
class AuthenticateUser
  prepend SimpleCommand

  def initialize(email, password)
    @email = email
    @password = password
  end

  def call
    # byebug
    JsonWebToken.encode(user_id: user.id.to_s) if user
  end

  private

  attr_accessor :email, :password

  def user
    user = User.find_by(:email => email)
    # byebug
    return user if user && user.authenticate(password)

    errors.add :user_authentication, 'invalid credentials'
    nil
  end
end

```

## 5. Verificando la autorización del usuario
---
La creación del token está hecha, pero no hay manera de verificar si un token que se ha agregado a una solicitud es válido. El comando de autorización debe tomar los encabezados de la solicitud y decodificar el token utilizando el método de decodificación en el singleton JsonWebToken.

```
# app/commands/authorize_api_request.rb

class AuthorizeApiRequest
  prepend SimpleCommand

  def initialize(headers = {})
    @headers = headers
  end

  def call
    user
  end

  private

  attr_reader :headers

  def user
    @user ||= User.find(decoded_auth_token[:user_id]) if decoded_auth_token
    @user || errors.add(:token, 'Invalid token') && nil
  end

  def decoded_auth_token
    @decoded_auth_token ||= JsonWebToken.decode(http_auth_header)
  end

  def http_auth_header
    if headers['Authorization'].present?
      return headers['Authorization'].split(' ').last
    else
      errors.add(:token, 'Missing token')
    end
    nil
  end
end
```
## 6. Implementando métodos de ayuda en los controladores
---
Toda la lógica para manejar tokens JWT ha sido establecida. Es hora de implementarlo en los controladores y ponerlo en uso real. 

Las dos piezas más esenciales para implementar son identificar el inicio de sesión del usuario y hacer referencia al usuario actual. 

* ### Iniciando sesión en usuarios 

Primero, comencemos con el inicio de sesión del usuario:
```
# app/controllers/authentication_controller.rb

class AuthenticationController < ApplicationController
 skip_before_action :authenticate_request

 def authenticate
   command = AuthenticateUser.call(params[:email], params[:password])

   if command.success?
     render json: { auth_token: command.result }
   else
     render json: { error: command.errors }, status: :unauthorized
   end
 end
end
```
*routes*
```
#config/routes.rb
  post 'authenticate', to: 'authentication#authenticate'
```

* ### Autorizando solicitudes

Para usar el token, debe haber un método current_user que 'persista' al usuario. Para que current_user esté disponible para todos los controladores, debe declararse en ApplicationController:
```
#app/controllers/application_controller.rb
class ApplicationController < ActionController::API
 before_action :authenticate_request
  attr_reader :current_user

  private

  def authenticate_request
    @current_user = AuthorizeApiRequest.call(request.headers).result
    render json: { error: 'Not Authorized' }, status: 401 unless @current_user
  end
end

```