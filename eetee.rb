require 'sinatra'
require 'oauth2'
require 'haml'
require 'sass'
require 'digest/md5'

require './config_manager'
require './socrata_request_serializer_middleware'




class Eetee < Sinatra::Base

# APPLICATION ENDPOINTS
  # display the form if they are logged in.
  get '/' do
    with_access_token do |access_token|
      # request current user to ensure our auth is still current.
      access_token.get '/api/users/current.json'

      # now return our result if we're okay.
      send_file 'views/input-form.html'
    end

    haml :index
  end

  get '/thanks' do
    haml :thanks
  end

  # page that uses an obtained access_token to update the calendar.
  post '/form' do
    unless params.nil?
 
 # get those params into nested JSON   

	#first we need brackets
	result = {}
	# split things up at the colons
	params.each do |key, val|
	  keys = key.to_s.split(':').map{ |k| k.to_sym }
	  
	  # Use the pop method to remove the last element in the array and return it
	  last_key = keys.pop
 
 	  #recursion to nest the arrays
	  pointer = result
	  keys.each do |subkey|
		pointer[subkey] = {} if pointer[subkey].nil?
		pointer = pointer[subkey]
	  end
 
	  pointer[last_key] = val
	end
      
    begin # sendoff
          
        with_access_token do |access_token|
         # access_token.put "/api/users/#{params[:user_id]}.json", { :description => params[:user_description] }

	  	 #send to Socrata
	  	 response = access_token.post "https://data.kingcounty.gov/resource/rnmi-uwsb.json", result

		# debuggery
		#return result.inspect

	#end sendoff
	end
	
	
      rescue OAuth2::HTTPError => ex
        @error = "An error has occured while attempting to update: #{ex.message}"
        return haml :error
      #end rescue
      end
    
    #end unless params  
    end
    redirect '/thanks'
  
  #end form
  end
  
  #----------------------------------
  

  # page that uses an obtained access_token to update the user's description.
  post '/update' do
    unless params[:user_id].nil? or params[:user_description].nil?
      begin
        with_access_token do |access_token|
          access_token.put "/api/users/#{params[:user_id]}.json", { :description => params[:user_description] }
	end
      rescue OAuth2::HTTPError => ex
        @error = "An error has occured while attempting to update: #{ex.message}"
        return haml :error
      end
    end

    redirect '/'
  end

  # just an endpoint to render out our application's styles.
  get '/styles.css' do
    response.headers['Content-Type'] = 'text/css; charset=utf-8'
    sass :styles
  end

# OAUTH ENDPOINTS
  # local endpoint that simply forms the correct url to send the user to for application
  # authorization, and then does so. note that redirect_uri is a private method found
  # later in this class; it ensures that the redirect_uri is validly formed.
  get '/auth' do
    redirect client.web_server.authorize_url :redirect_uri => redirect_uri,
                                             :response_type => 'code'
  end

  # redirect_uri points here. if the user rejects the application, a code will not be
  # supplied, so simply send them back to the application root. if we get a code,
  # immediately turn around and request an access token, then save the raw string of
  # the token in the user's session cookie. then, redirect to a page showing them some
  # basic details about them.
  get '/auth/callback' do
    redirect '/' if params[:code].nil? || (params[:code] == '')

    begin
      access_token = client.web_server.get_access_token params[:code],
                                                        :redirect_uri => redirect_uri,
                                                        :grant_type => 'authorization_code'
    rescue OAuth2::HTTPError => ex
      @error = "An error has occured while attempting to authenticate: #{ex.message}"
      return haml :error
    end

    session[:access_token] = access_token.token
    redirect '/'
  end

private

  # create an oauth2 client that points to the site we want to access, and has our
  # various tokens on hand.
  def client
    client = OAuth2::Client.new ::ConfigManager['socrata_auth_token'],
                                ::ConfigManager['socrata_secret_token'],
                                :site => ::ConfigManager['socrata_powered_site']

    # in order to ease access to SODA (which primarily uses JSON), we use a faraday
    # middleware adapter that smooths over some of the oauth2 gem's quirks. see that
    # class for details.
    client.connection.build do |builder|
      builder.use SocrataRequestSerializerMiddleware
      builder.adapter Faraday.default_adapter
    end

    return client
  end

  # simple helper that attempts to execute an api call. if the user is unauthenticated,
  # it will simply do nothing; likewise, if a user's authentication has expired, it will
  # delete the saved token and do nothing.
  def with_access_token
    return if session[:access_token].nil?

    # catch 401's; they usually mean the token has expired
    # catch 403's with a body of "Bad OAuth token"; same deal
    # leave the rest to be handled by the caller
    begin
      yield OAuth2::AccessToken.new client, session[:access_token]
    rescue OAuth2::AccessDenied => ex
      halt clear_auth!
    rescue OAuth2::HTTPError => ex
      if (JSON.parse ex.response.body)['message'] == "Bad OAuth token"
        halt clear_auth!
      else
        throw ex
      end
    end
  end

  # clears auth and shows an error if we think the oauth token is dead.
  def clear_auth!
    session[:access_token] = nil
    @error = "It looks like your login has expired. You will need to log back in."
    return haml :error
  end

  # simple helper to ensure that our redirect_uri is well-formed. take our current url,
  # change the path to what our local callback endpoint is (this can be anything, as
  # long as the server is set up to handle requests there), and ensure that we're 
  # making our request in https.
  def redirect_uri
    uri = URI.parse request.url
    uri.path = '/auth/callback'
#   uri.path = '/calendar/index.html'
    uri.query = nil
    uri.scheme = 'https'

    return uri.to_s
  end
end
