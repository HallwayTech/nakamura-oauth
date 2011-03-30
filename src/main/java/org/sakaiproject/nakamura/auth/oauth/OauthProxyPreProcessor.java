/*
 * Licensed to the Sakai Foundation (SF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The SF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.sakaiproject.nakamura.auth.oauth;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableMap.Builder;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Service;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.osgi.framework.BundleContext;
import org.sakaiproject.nakamura.api.proxy.ProxyPreProcessor;
import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.Api;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;

import java.util.Map;

/**
 * Proxy pre-processor to handle the OAuth dance based on
 * http://dret.net/lectures/mobapp-spring10/img/oauth-diagram.png.
 * 
 * Provider names expected include:
 * <ul>
 *   <li>evernote</li>
 *   <li>facebook</li>
 *   <li>foursquare</li>
 *   <li>google</li>
 *   <li>linkedin</li>
 *   <li>twitter</li>
 *   <li>vimeo</li>
 *   <li>yahoo</li>
 *   <li>yammer</li>
 * </ul>
 */
@Component(configurationFactory = true)
@Service
@Properties({
  @Property(name = OauthProxyPreProcessor.NAME),
  @Property(name = OauthProxyPreProcessor.PROVIDER),
  @Property(name = OauthProxyPreProcessor.API_KEY),
  @Property(name = OauthProxyPreProcessor.API_SECRET),
  @Property(name = OauthProxyPreProcessor.SCOPE),
  @Property(name = OauthProxyPreProcessor.CALLBACK)
})
public class OauthProxyPreProcessor implements ProxyPreProcessor {
  public static final String NAME = "name";
  public static final String PROVIDER = "provider";
  public static final String API_KEY = "api.key";
  public static final String API_SECRET = "api.secret";
  public static final String SCOPE = "scope";
  public static final String CALLBACK = "callback";

  private String name;
  private Class<? extends Api> providerClass;
  private String apiKey;
  private String apiSecret;
  private String callback;
  private OAuthService service;

  private Map<String, Class<? extends Api>> providers;
  
  public OauthProxyPreProcessor() {
    Builder<String, Class<? extends Api>> builder = ImmutableMap.builder();
    builder.put("evernote", org.scribe.builder.api.EvernoteApi.class)
        .put("facebook", org.scribe.builder.api.FacebookApi.class)
        .put("foursquare", org.scribe.builder.api.FoursquareApi.class)
        .put("google", org.scribe.builder.api.GoogleApi.class)
        .put("linkedin", org.scribe.builder.api.LinkedInApi.class)
        .put("twitter", org.scribe.builder.api.TwitterApi.class)
        .put("vimeo", org.scribe.builder.api.VimeoApi.class)
        .put("yahoo", org.scribe.builder.api.YahooApi.class)
        .put("yammer", org.scribe.builder.api.YammerApi.class);
     providers = builder.build();
  }

  @SuppressWarnings("unchecked")
  @Activate
  protected void activate(BundleContext bundleContext) throws ClassNotFoundException {
    String provider = OsgiUtil.toString(PROVIDER, null);
    providerClass = bundleContext.getBundle().loadClass(provider);

    name = OsgiUtil.toString(NAME, null);

    apiKey = OsgiUtil.toString(API_KEY, null);
    apiSecret = OsgiUtil.toString(API_SECRET, null);

    ServiceBuilder sb = new ServiceBuilder().provider(providerClass).apiKey(apiKey)
        .apiSecret(apiSecret);

    // callback is used with facebook
    if (callback != null) {
      sb.callback(callback);
    }

    service = sb.build();
  }

  /**
   * {@inheritDoc}
   * 
   * @see org.sakaiproject.nakamura.api.proxy.ProxyPreProcessor#preProcessRequest(org.apache.sling.api.SlingHttpServletRequest,
   *      java.util.Map, java.util.Map)
   */
  public void preProcessRequest(SlingHttpServletRequest httpRequest,
      Map<String, String> headers, Map<String, Object> templateParams) {
    // TODO find out how to get the proxy service to use an oauth request

    // 1. Consumer requests request token
    // 2. Service provider grants request token
    Token requestToken = service.getRequestToken();

    // 3. Consumer directs user to service provider
    String authzUrl = service.getAuthorizationUrl(requestToken);
    // 4. Service provider directs user to consumer
    // TODO send user to authz url and collect the authorization code
    String authzCode = "some verification value";

    // 5. Consumer requests access token
    Verifier verifier = new Verifier(authzCode);

    // 6. Service provider grants access token
    Token accessToken = service.getAccessToken(requestToken, verifier);

    // 7. Consumer accesses protected resources
    OAuthRequest request = new OAuthRequest(Verb.GET, "this is set on the proxy node");
    service.signRequest(accessToken, request);
    Response response = request.send();

    response.getCode();
    response.getBody();
  }

  /**
   * {@inheritDoc}
   * 
   * @see org.sakaiproject.nakamura.api.proxy.ProxyPreProcessor#getName()
   */
  public String getName() {
    return name;
  }
}
