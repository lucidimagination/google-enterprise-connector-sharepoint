<%@ Page Language="C#" Inherits="System.Web.UI.Page"%>
<%@ Assembly Name="Microsoft.SharePoint, Version=11.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %> <%@ Import Namespace="Microsoft.SharePoint.Utilities" %> <%@ Import Namespace="Microsoft.SharePoint" %>
<% Response.ContentType = "text/xml"; %>
<wsdl:definitions xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:tm="http://microsoft.com/wsdl/mime/textMatching/" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:mime="http://schemas.xmlsoap.org/wsdl/mime/" xmlns:tns="gsbulkauthorization.generated.sharepoint.connector.enterprise.google.com" xmlns:s="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/" xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" targetNamespace="gsbulkauthorization.generated.sharepoint.connector.enterprise.google.com" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">
  <wsdl:types>
    <s:schema elementFormDefault="qualified" targetNamespace="gsbulkauthorization.generated.sharepoint.connector.enterprise.google.com">
      <s:element name="Authorize">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="0" maxOccurs="1" name="authData" type="tns:AuthData" />
            <s:element minOccurs="0" maxOccurs="1" name="loginId" type="s:string" />
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:complexType name="AuthData">
        <s:sequence>
          <s:element minOccurs="0" maxOccurs="1" name="listURL" type="s:string" />
          <s:element minOccurs="0" maxOccurs="1" name="listItemId" type="s:string" />
          <s:element minOccurs="1" maxOccurs="1" name="isAllowed" type="s:boolean" />
          <s:element minOccurs="0" maxOccurs="1" name="error" type="s:string" />
          <s:element minOccurs="0" maxOccurs="1" name="complexDocId" type="s:string" />
        </s:sequence>
      </s:complexType>
      <s:element name="AuthorizeResponse">
        <s:complexType />
      </s:element>
      <s:element name="BulkAuthorize">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="0" maxOccurs="1" name="authData" type="tns:ArrayOfAuthData" />
            <s:element minOccurs="0" maxOccurs="1" name="loginId" type="s:string" />
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:complexType name="ArrayOfAuthData">
        <s:sequence>
          <s:element minOccurs="0" maxOccurs="unbounded" name="AuthData" nillable="true" type="tns:AuthData" />
        </s:sequence>
      </s:complexType>
      <s:element name="BulkAuthorizeResponse">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="0" maxOccurs="1" name="BulkAuthorizeResult" type="tns:ArrayOfAuthData" />
          </s:sequence>
        </s:complexType>
      </s:element>
      <s:element name="CheckConnectivity">
        <s:complexType />
      </s:element>
      <s:element name="CheckConnectivityResponse">
        <s:complexType>
          <s:sequence>
            <s:element minOccurs="0" maxOccurs="1" name="CheckConnectivityResult" type="s:string" />
          </s:sequence>
        </s:complexType>
      </s:element>
    </s:schema>
  </wsdl:types>
  <wsdl:message name="AuthorizeSoapIn">
    <wsdl:part name="parameters" element="tns:Authorize" />
  </wsdl:message>
  <wsdl:message name="AuthorizeSoapOut">
    <wsdl:part name="parameters" element="tns:AuthorizeResponse" />
  </wsdl:message>
  <wsdl:message name="BulkAuthorizeSoapIn">
    <wsdl:part name="parameters" element="tns:BulkAuthorize" />
  </wsdl:message>
  <wsdl:message name="BulkAuthorizeSoapOut">
    <wsdl:part name="parameters" element="tns:BulkAuthorizeResponse" />
  </wsdl:message>
  <wsdl:message name="CheckConnectivitySoapIn">
    <wsdl:part name="parameters" element="tns:CheckConnectivity" />
  </wsdl:message>
  <wsdl:message name="CheckConnectivitySoapOut">
    <wsdl:part name="parameters" element="tns:CheckConnectivityResponse" />
  </wsdl:message>
  <wsdl:portType name="BulkAuthorizationSoap">
    <wsdl:operation name="Authorize">
      <wsdl:input message="tns:AuthorizeSoapIn" />
      <wsdl:output message="tns:AuthorizeSoapOut" />
    </wsdl:operation>
    <wsdl:operation name="BulkAuthorize">
      <wsdl:input message="tns:BulkAuthorizeSoapIn" />
      <wsdl:output message="tns:BulkAuthorizeSoapOut" />
    </wsdl:operation>
    <wsdl:operation name="CheckConnectivity">
      <wsdl:input message="tns:CheckConnectivitySoapIn" />
      <wsdl:output message="tns:CheckConnectivitySoapOut" />
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="BulkAuthorizationSoap" type="tns:BulkAuthorizationSoap">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http" />
    <wsdl:operation name="Authorize">
      <soap:operation soapAction="gsbulkauthorization.generated.sharepoint.connector.enterprise.google.com/Authorize" style="document" />
      <wsdl:input>
        <soap:body use="literal" />
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal" />
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="BulkAuthorize">
      <soap:operation soapAction="gsbulkauthorization.generated.sharepoint.connector.enterprise.google.com/BulkAuthorize" style="document" />
      <wsdl:input>
        <soap:body use="literal" />
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal" />
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="CheckConnectivity">
      <soap:operation soapAction="gsbulkauthorization.generated.sharepoint.connector.enterprise.google.com/CheckConnectivity" style="document" />
      <wsdl:input>
        <soap:body use="literal" />
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal" />
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:binding name="BulkAuthorizationSoap12" type="tns:BulkAuthorizationSoap">
    <soap12:binding transport="http://schemas.xmlsoap.org/soap/http" />
    <wsdl:operation name="Authorize">
      <soap12:operation soapAction="gsbulkauthorization.generated.sharepoint.connector.enterprise.google.com/Authorize" style="document" />
      <wsdl:input>
        <soap12:body use="literal" />
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal" />
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="BulkAuthorize">
      <soap12:operation soapAction="gsbulkauthorization.generated.sharepoint.connector.enterprise.google.com/BulkAuthorize" style="document" />
      <wsdl:input>
        <soap12:body use="literal" />
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal" />
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="CheckConnectivity">
      <soap12:operation soapAction="gsbulkauthorization.generated.sharepoint.connector.enterprise.google.com/CheckConnectivity" style="document" />
      <wsdl:input>
        <soap12:body use="literal" />
      </wsdl:input>
      <wsdl:output>
        <soap12:body use="literal" />
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="BulkAuthorization">
    <wsdl:port name="BulkAuthorizationSoap" binding="tns:BulkAuthorizationSoap">
		<soap:address location=<% SPEncode.WriteHtmlEncodeWithQuote(Response, SPWeb.OriginalBaseUrl(Request), '"'); %> />
	</wsdl:port>
    <wsdl:port name="BulkAuthorizationSoap12" binding="tns:BulkAuthorizationSoap12">
		<soap12:address location=<% SPEncode.WriteHtmlEncodeWithQuote(Response, SPWeb.OriginalBaseUrl(Request), '"'); %> />
	</wsdl:port>
  </wsdl:service>
</wsdl:definitions>