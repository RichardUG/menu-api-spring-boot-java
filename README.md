# IMPLEMENTING JWT AUTHENTICATION ON SPRING BOOT

## Descripción

El proyecto consta de aprender como proteger una aplicación con autenticación y autorización a traves de Auth0 y JWT de springboot para restringir el acceso a un sistema y a la vez poder limitar las acciones que un usuario autenticado puede hacer dentro de un sistema

Este proyecto lo hacemos gracias a la guia que se encuentra publicada en [Spring Boot Authorization Tutorial: Secure an API (Java)](https://auth0.com/blog/spring-boot-authorization-tutorial-secure-an-api-java/) y al repositorio que habian trabajado con anterioridad que esta en [menu-api-spring-boot-java](menu-api-spring-boot-java)

## Prerrequisitos

* Descargar el repositorio con el que se va a trabajar el laboratorio - [menu-api-spring-boot-java](menu-api-spring-boot-java)
* Crear una cuenta en [Auth0](https://auth0.com/signup)

## Creando nuestro ambiente

  Vamos a crear una nueva API con nombre "Menu API" e identifier "https://menu-api.example.com"
  
  ![](/img/1.PNG)

  Creamos una nueva aplicación de tipo Single Page Web Application con el nombre "WHATABYTE Demo Client" 

  ![](/img/2.PNG)

  Agregamos lo siguiente a nuestra application.properties

  ```
  server.port=7000
  auth0.audience=
  auth0.domain=
  spring.security.oauth2.resourceserver.jwt.issuer-uri=https://${auth0.domain}/
  ```
  
  a audience le agregamos el valor de identifier que encontramos en el setting de nuestra API y al domain le agregamos el domain que podemos observa en las pruebas 

  ![](/img/36.PNG)

## Spring Boot and authorization

  Después agregamos el jwt a nuestro proyecto a través de las dependencias de gradle

  ```gradle
  implementation 'org.springframework.boot:spring-boot-starter-security'
  implementation 'org.springframework.security:spring-security-oauth2-resource-server'
  implementation 'org.springframework.security:spring-security-oauth2-jose'
  ```

  Creamos un paquete llamado Security y en él una clase llamada SecurityConfig con el siguiente código que se encargara de habilitar la seguridad web al proyecto

  ```java
  package com.example.menu.security;

  import org.springframework.http.HttpMethod;
  import org.springframework.security.config.annotation.web.builders.HttpSecurity;
  import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
  import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
  
  @EnableWebSecurity
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
     @Override
     protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
        .mvcMatchers(HttpMethod.GET, "/api/menu/items/**").permitAll() // GET requests don't need auth
        .anyRequest()
        .authenticated()
        .and()
        .oauth2ResourceServer()
        .jwt();
     }
  }
  ```
  
  ahora creamos una nueva clase llamada AudienceValidator que se encargara de validar que tokens son validos para permitir el acceso

  ```java
  package com.example.menu.security;

  import org.springframework.security.oauth2.core.OAuth2Error;
  import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
  import org.springframework.security.oauth2.core.OAuth2TokenValidator;
  import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
  import org.springframework.security.oauth2.jwt.Jwt;
  
  import java.util.List;
  import java.util.Objects;
  
  class AudienceValidator implements OAuth2TokenValidator<Jwt> {
    private final String audience;
  
    AudienceValidator(String audience) {
        Assert.hasText(audience, "audience is null or empty");
        this.audience = audience;
    }
  
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> audiences = jwt.getAudience();
        if (audiences.contains(this.audience)) {
            return OAuth2TokenValidatorResult.success();
        }
        OAuth2Error err = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN);
        return OAuth2TokenValidatorResult.failure(err);
    }
  }
  ```
  
  Ahora que creamos el validador de los tokens debemos agrgar lo siguiente a nuestra clase SecurityConfig para que decifre y envie a validar los tokens que se obtienen

  ```java
  package com.example.menu.security;

  import org.springframework.beans.factory.annotation.Value;
  import org.springframework.http.HttpMethod;
  import org.springframework.security.config.annotation.web.builders.HttpSecurity;
  import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
  import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
  import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
  import org.springframework.security.oauth2.core.OAuth2TokenValidator;
  import org.springframework.security.oauth2.jwt.*;
  
  @EnableWebSecurity
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Value("${auth0.audience}")
    private String audience;
  
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;
  
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
        .mvcMatchers(HttpMethod.GET, "/api/menu/items/**").permitAll() // GET requests don't need auth
        .anyRequest()
        .authenticated()
        .and()
        .oauth2ResourceServer()
        .jwt()
        .decoder(jwtDecoder());
    }
  
    JwtDecoder jwtDecoder() {
      OAuth2TokenValidator<Jwt> withAudience = new AudienceValidator(audience);
      OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
      OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withAudience, withIssuer);
  
      NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);
      jwtDecoder.setJwtValidator(validator);
      return jwtDecoder;
    }
  }
  ```
  ejecutamos nuevamente nuestra aplicación con ```./gradlew bootRun``` y probamos enviando una petición POST a través de POSTMAN que nos retorna un error 401 ya que no estamos autorizados

  ![](/img/3.PNG)


## Registramos nuestro cliente con la aplicación Auth0
  
  Ahora nos dirigimos a [https://dashboard.whatabyte.app/](https://dashboard.whatabyte.app/) y editamos los valore Domain y Client ID con los valores que nos brinda la aplicación que creamos en su pestaña de settings, Auth0 API Audience será https://menu-api.example.com y Auth0 Callback URL es https://dashboard.whatabyte.app/home

  ![](/img/4.PNG)

  y trás guardar las configuraciones podremos ver nuestro dashboard 

  ![](/img/5.PNG)

  Ahora cuál vamos a modificar los settings de la aplicación que creamos y la vamos a dejar del siguiente modo

  ![](/img/6.PNG)


## Habilitar CORS de Spring Boot

  Debemos habilitar los CORS para que nuestro API pueda recibir las consultas externas debido a la seguridad que hemos implementado, por lo cual vamos a agregar lo siguiente al código

  ```java
  package com.example.menu.security;
  
  import org.springframework.beans.factory.annotation.Value;
  import org.springframework.http.HttpMethod;
  import org.springframework.security.config.annotation.web.builders.HttpSecurity;
  import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
  import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
  import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
  import org.springframework.security.oauth2.core.OAuth2TokenValidator;
  import org.springframework.security.oauth2.jwt.*;
  import org.springframework.web.cors.CorsConfiguration;
  import org.springframework.web.cors.CorsConfigurationSource;
  import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
  
  import java.util.List;
  
  @EnableWebSecurity
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
  @Value("${auth0.audience}")
  private String audience;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers(HttpMethod.GET, "/api/menu/items/**").permitAll() // GET requests don't need auth
                .anyRequest()
                .authenticated()
                .and()
                .cors()
                .configurationSource(corsConfigurationSource())
                .and()
                .oauth2ResourceServer()
                .jwt()
                .decoder(jwtDecoder());
    }

    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedMethods(List.of(
                HttpMethod.GET.name(),
                HttpMethod.PUT.name(),
                HttpMethod.POST.name(),
                HttpMethod.DELETE.name()
        ));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration.applyPermitDefaultValues());
        return source;
    }

    JwtDecoder jwtDecoder() {
        OAuth2TokenValidator<Jwt> withAudience = new AudienceValidator(audience);
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withAudience, withIssuer);

        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);
        jwtDecoder.setJwtValidator(validator);
        return jwtDecoder;
    }
  }
  ```

  Y ya que hemos asociado nuestra aplicación no necesitamos más tener un cross origin por lo cual podemos borrrar la siguiente linea de la clase "ItemsController"

  ```
  @CrossOrigin(origins = "https://dashboard.whatabyte.app")
  ```

## Sign in

  Tras esto nos podremos registrar, en mi caso lo registré de manera manual con usuario y contraseña

  ![](/img/7.PNG)

  Al acceder podremos ver nuestro perfil

  ![](/img/8.PNG)

  En este punto somos capaces de hacer cualquier operación CRUD en la plataforma

## Probando la protección del end point

  Saldremos de la sesión y deshabilitaremos los parametros de autenticación 

  ![](/img/9.PNG)

  Ahora ingresaremos otra vez y al intentar agregar un nuevo elemento no lo podremos hacer

  ![](/img/11.PNG)

  Del mismo modo sí intentamos editar o eliminar un elemento ya existente

  ![](/img/12.PNG)

  Ahora volveremos a ajustar nuestros parametros de Authentication Features

## Configure Role-Based Access Control (RBAC)

  Lo primero que debemos hacer es habilitar las opciones "Enable RBAC" y "Add permisions in the access token" en los settings de la API que creamos

  ![](/img/14.PNG)

  Ahora agregaremos los permisos necesarios a nuestra API

  ![](/img/13.PNG)

  Después crearemos un nuevo Rol llamado "menu-admin"

  ![](/img/15.PNG)

  Y despues le agregaremos los permisos de nuestra API a nuestro ROL

  ![](/img/16.PNG)

  Lo veremos del siguiente modo

  ![](/img/26.PNG)

## Creación de una acción

  En el tutorial nos mostraba que debiamos crear una regla que se ejecutaria tras un login exitoso, pero estas reglas ya no funcionan mas en la versión actual de auth, por lo cual debemos crear una acción

  Nos vamos a dirigir al menu actions -> Library 

  ![](/img/24.PNG)

  Después vamos a oprimir la opción Build Custom y a esta acción le vamos a dar el nombre de "Add user roles to tokens" como un Trigger de tipo "Login / Post Login"

  ![](/img/25.PNG)

  Tras ingresar tendremos que cambiar el código que nos brindaban en el tutorial, el codigo es el que esta a continuación y sirve para que cuando un login es exitoso valide los roles del usuario y en caso de ser de tipo admin le proporcione los permisos necesarios

  ```jshelllanguage
  /**
  * Handler that will be called during the execution of a PostLogin flow.
  *
  * @param {Event} event - Details about the user and the context in which they are logging in.
  * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
  */
  exports.onExecutePostLogin = async (event, api) => {
    authorize(event, api,function(err, result) {
      return result;   
    })
  };
  
  function authorize(event, api, callback) {
    
    const namespace = 'https://menu-api.example.com';
    
    const promise = new Promise(()=>{
        if (event.authorization && event.authorization.roles) {
          const assignedRoles = event.authorization.roles;
          if (api.idToken) {
            api.idToken.setCustomClaim(`${namespace}/roles`, assignedRoles);
          }
          if (api.accessToken) {
            api.accessToken.setCustomClaim(`${namespace}/roles`, assignedRoles);
          }    
        }
      }
    );
    promise.then(callback(null, event, api));
  }
  
  /**
  * Handler that will be invoked when this action is resuming after an external redirect. If your
  * onExecutePostLogin function does not perform a redirect, this function can be safely ignored.
  *
  * @param {Event} event - Details about the user and the context in which they are logging in.
  * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
  */
  // exports.onContinuePostLogin = async (event, api) => {
  // };
  ```

  Guardaremos nuestra acción y después nos dirigiremos al menú Actions->Flows->Login y agregaremos nuestra acción
  
  ![](/img/18.PNG)

  Después volveremos a nuestro menú de "Auth Demo Settings" y habilitaremos la opción RBAC y como Rol agregaremos "menu-admin"

  ![](/img/19.PNG)

  Ahora si ingresamos nuevamente no tendremos la opción de "Add item", "Edit" o "Delete" ya que nuestro usuario no esta asociado al rol de admin

  ![](/img/20.PNG)

  ![](/img/21.PNG)

## Admin user

  Ahora nos dirigiremos a crear  un nuevo usuario de tipo admin, con el correo "admin@example.com" y connection "Username-Password-Authentication"

  ![](/img/22.PNG)

  Luego iremos a el rol que habiamos creado y le agregaremos nuestro usuario admin
  
  ![](/img/23.PNG)

  Al entrar con este usuario a la plataforma veremos nuestra opción de "ADD ITEM" nuevamente, crearemos el que esta por defecto

  ![](/img/27.PNG)

  ![](/img/28.PNG)

  Y en la hamburguesa editaremos de "tasty" por "super tasty"

  ![](/img/29.PNG)

  ![](/img/30.PNG)

  Podremos observar que los cambios se han guardado

  ![](/img/31.PNG)

## Implement Role-Based Access Control in Spring Boot

  A pesar de que ya agregamos seguridad a nuestra aplicación Auth, aun es posible omitir esta autorización en nuestro proyecto, por lo cual debemos hacer algunos cambios

  Primero editaremos nuestro archivo SecurityConfig para que reconozca los authorities a través del scope de la consulta

  ```java
  package com.example.menu.security;

  import org.springframework.beans.factory.annotation.Value;
  import org.springframework.http.HttpMethod;
  import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
  import org.springframework.security.config.annotation.web.builders.HttpSecurity;
  import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
  import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
  import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
  import org.springframework.security.oauth2.core.OAuth2TokenValidator;
  import org.springframework.security.oauth2.jwt.Jwt;
  import org.springframework.security.oauth2.jwt.JwtDecoder;
  import org.springframework.security.oauth2.jwt.JwtDecoders;
  import org.springframework.security.oauth2.jwt.JwtValidators;
  import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
  import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
  import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
  import org.springframework.web.cors.CorsConfiguration;
  import org.springframework.web.cors.CorsConfigurationSource;
  import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
  
  import java.util.List;
  
  @EnableWebSecurity
  @EnableGlobalMethodSecurity(prePostEnabled = true)
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Value("${auth0.audience}")
    private String audience;
  
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuer;
  
    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.authorizeRequests()
              .mvcMatchers(HttpMethod.GET, "/api/menu/items/**").permitAll() // GET requests don't need auth
              .anyRequest()
              .authenticated()
              .and()
              .cors()
              .configurationSource(corsConfigurationSource())
              .and()
              .oauth2ResourceServer()
              .jwt()
              .decoder(jwtDecoder())
              .jwtAuthenticationConverter(jwtAuthenticationConverter());
    }
  
    CorsConfigurationSource corsConfigurationSource() {
      CorsConfiguration configuration = new CorsConfiguration();
      configuration.setAllowedMethods(List.of(
              HttpMethod.GET.name(),
              HttpMethod.PUT.name(),
              HttpMethod.POST.name(),
              HttpMethod.DELETE.name()
      ));
  
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", configuration.applyPermitDefaultValues());
      return source;
    }
  
    JwtDecoder jwtDecoder() {
      OAuth2TokenValidator<Jwt> withAudience = new AudienceValidator(audience);
      OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
      OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(withAudience, withIssuer);
  
      NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromOidcIssuerLocation(issuer);
      jwtDecoder.setJwtValidator(validator);
      return jwtDecoder;
    }
  
    JwtAuthenticationConverter jwtAuthenticationConverter() {
      JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
      converter.setAuthoritiesClaimName("permissions");
      converter.setAuthorityPrefix("");
  
      JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
      jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
      return jwtConverter;
    }
  }
  ```

  Y luego en nuestro archivo ItemController agregaremos la etiqueta ```@PreAuthorize``` a aquellos end points que lo requieran, junto con su permiso

  ```java
  package com.example.menu.item;
  
  import org.springframework.http.ResponseEntity;
  import org.springframework.security.access.prepost.PreAuthorize;
  import org.springframework.validation.FieldError;
  import org.springframework.validation.ObjectError;
  import org.springframework.web.bind.MethodArgumentNotValidException;
  import org.springframework.web.bind.annotation.*;
  import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
  
  import javax.validation.Valid;
  import java.net.URI;
  import java.util.HashMap;
  import java.util.List;
  import java.util.Map;
  import java.util.Optional;
  @RestController
  @RequestMapping("api/menu/items")
  public class ItemController {
    private final ItemService service;
  
    public ItemController(ItemService service) {
      this.service = service;
    }
  
    @GetMapping
    public ResponseEntity<List<Item>> findAll() {
      List<Item> items = service.findAll();
      return ResponseEntity.ok().body(items);
    }
  
    @GetMapping("/{id}")
    public ResponseEntity<Item> find(@PathVariable("id") Long id) {
      Optional<Item> item = service.find(id);
      return ResponseEntity.of(item);
    }
  
    @PostMapping
    @PreAuthorize("hasAuthority('create:items')")
    public ResponseEntity<Item> create(@Valid @RequestBody Item item) {
      Item created = service.create(item);
      URI location = ServletUriComponentsBuilder.fromCurrentRequest()
              .path("/{id}")
              .buildAndExpand(created.getId())
              .toUri();
      return ResponseEntity.created(location).body(created);
    }
  
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('update:items')")
    public ResponseEntity<Item> update(
            @PathVariable("id") Long id,
            @Valid @RequestBody Item updatedItem) {
  
      Optional<Item> updated = service.update(id, updatedItem);
  
      return updated
              .map(value -> ResponseEntity.ok().body(value))
              .orElseGet(() -> {
                Item created = service.create(updatedItem);
                URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                        .path("/{id}")
                        .buildAndExpand(created.getId())
                        .toUri();
                return ResponseEntity.created(location).body(created);
              });
    }
  
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('delete:items')")
    public ResponseEntity<Item> delete(@PathVariable("id") Long id) {
      service.delete(id);
      return ResponseEntity.noContent().build();
    }
  
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
      List<ObjectError> errors = ex.getBindingResult().getAllErrors();
      Map<String, String> map = new HashMap<>(errors.size());
      errors.forEach((error) -> {
        String key = ((FieldError) error).getField();
        String val = error.getDefaultMessage();
        map.put(key, val);
      });
      return ResponseEntity.badRequest().body(map);
    }
  }
  ```

  Volveremos a ejecutar nuestra aplicación con ```gradlew bootRun``` y trataremos de crear un nuevo producto con los siguientes datos

  ```
  name: Coffee
  price: 299
  description: Woke
  image: https://images.ctfassets.net/23aumh6u8s0i/6HS0xLG6bx52KJrqyqfznk/50f9350a7791fa86003024af4762f4ca/whatabyte_coffee-sm.png
  ```

  ![](/img/32.PNG)

  El producto se crea de manera satisfactoria

  ![](/img/33.PNG)

## Desactivando nuestro tol

  Saldremos de la sesión y desactivaremos nuestro RBAC desde los settings de nuestra plataforma

  ![](/img/34.PNG)

  Volveremos a entrar pero con nuestro usuario non-admin, esto para validar que aunque quitemos el rol, la protección de nuestra API sigue siendo estable

  ![](/img/35.PNG)


## Autor
[Richard Santiago Urrea Garcia](https://github.com/RichardUG)
## Licencia & Derechos de Autor
**©** Richard Santiago Urrea Garcia, Ingeniero de Sistemas

Licencia bajo la [GNU General Public License](https://github.com/RichardUG/menu-api-spring-boot-java/blob/main/LICENSE).