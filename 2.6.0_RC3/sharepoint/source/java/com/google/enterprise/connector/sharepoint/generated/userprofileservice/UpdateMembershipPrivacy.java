/**
 * UpdateMembershipPrivacy.java
 *
 * This file was auto-generated from WSDL
 * by the Apache Axis 1.4 Apr 22, 2006 (06:55:48 PDT) WSDL2Java emitter.
 */

package com.google.enterprise.connector.sharepoint.generated.userprofileservice;

public class UpdateMembershipPrivacy  implements java.io.Serializable {
    private java.lang.String accountName;

    private java.lang.String sourceInternal;

    private java.lang.String sourceReference;

    private com.google.enterprise.connector.sharepoint.generated.userprofileservice.Privacy newPrivacy;

    public UpdateMembershipPrivacy() {
    }

    public UpdateMembershipPrivacy(
           java.lang.String accountName,
           java.lang.String sourceInternal,
           java.lang.String sourceReference,
           com.google.enterprise.connector.sharepoint.generated.userprofileservice.Privacy newPrivacy) {
           this.accountName = accountName;
           this.sourceInternal = sourceInternal;
           this.sourceReference = sourceReference;
           this.newPrivacy = newPrivacy;
    }


    /**
     * Gets the accountName value for this UpdateMembershipPrivacy.
     *
     * @return accountName
     */
    public java.lang.String getAccountName() {
        return accountName;
    }


    /**
     * Sets the accountName value for this UpdateMembershipPrivacy.
     *
     * @param accountName
     */
    public void setAccountName(java.lang.String accountName) {
        this.accountName = accountName;
    }


    /**
     * Gets the sourceInternal value for this UpdateMembershipPrivacy.
     *
     * @return sourceInternal
     */
    public java.lang.String getSourceInternal() {
        return sourceInternal;
    }


    /**
     * Sets the sourceInternal value for this UpdateMembershipPrivacy.
     *
     * @param sourceInternal
     */
    public void setSourceInternal(java.lang.String sourceInternal) {
        this.sourceInternal = sourceInternal;
    }


    /**
     * Gets the sourceReference value for this UpdateMembershipPrivacy.
     *
     * @return sourceReference
     */
    public java.lang.String getSourceReference() {
        return sourceReference;
    }


    /**
     * Sets the sourceReference value for this UpdateMembershipPrivacy.
     *
     * @param sourceReference
     */
    public void setSourceReference(java.lang.String sourceReference) {
        this.sourceReference = sourceReference;
    }


    /**
     * Gets the newPrivacy value for this UpdateMembershipPrivacy.
     *
     * @return newPrivacy
     */
    public com.google.enterprise.connector.sharepoint.generated.userprofileservice.Privacy getNewPrivacy() {
        return newPrivacy;
    }


    /**
     * Sets the newPrivacy value for this UpdateMembershipPrivacy.
     *
     * @param newPrivacy
     */
    public void setNewPrivacy(com.google.enterprise.connector.sharepoint.generated.userprofileservice.Privacy newPrivacy) {
        this.newPrivacy = newPrivacy;
    }

    private java.lang.Object __equalsCalc = null;
    public synchronized boolean equals(java.lang.Object obj) {
        if (!(obj instanceof UpdateMembershipPrivacy)) return false;
        UpdateMembershipPrivacy other = (UpdateMembershipPrivacy) obj;
        if (obj == null) return false;
        if (this == obj) return true;
        if (__equalsCalc != null) {
            return (__equalsCalc == obj);
        }
        __equalsCalc = obj;
        boolean _equals;
        _equals = true &&
            ((this.accountName==null && other.getAccountName()==null) ||
             (this.accountName!=null &&
              this.accountName.equals(other.getAccountName()))) &&
            ((this.sourceInternal==null && other.getSourceInternal()==null) ||
             (this.sourceInternal!=null &&
              this.sourceInternal.equals(other.getSourceInternal()))) &&
            ((this.sourceReference==null && other.getSourceReference()==null) ||
             (this.sourceReference!=null &&
              this.sourceReference.equals(other.getSourceReference()))) &&
            ((this.newPrivacy==null && other.getNewPrivacy()==null) ||
             (this.newPrivacy!=null &&
              this.newPrivacy.equals(other.getNewPrivacy())));
        __equalsCalc = null;
        return _equals;
    }

    private boolean __hashCodeCalc = false;
    public synchronized int hashCode() {
        if (__hashCodeCalc) {
            return 0;
        }
        __hashCodeCalc = true;
        int _hashCode = 1;
        if (getAccountName() != null) {
            _hashCode += getAccountName().hashCode();
        }
        if (getSourceInternal() != null) {
            _hashCode += getSourceInternal().hashCode();
        }
        if (getSourceReference() != null) {
            _hashCode += getSourceReference().hashCode();
        }
        if (getNewPrivacy() != null) {
            _hashCode += getNewPrivacy().hashCode();
        }
        __hashCodeCalc = false;
        return _hashCode;
    }

    // Type metadata
    private static org.apache.axis.description.TypeDesc typeDesc =
        new org.apache.axis.description.TypeDesc(UpdateMembershipPrivacy.class, true);

    static {
        typeDesc.setXmlType(new javax.xml.namespace.QName("http://microsoft.com/webservices/SharePointPortalServer/UserProfileService", ">UpdateMembershipPrivacy"));
        org.apache.axis.description.ElementDesc elemField = new org.apache.axis.description.ElementDesc();
        elemField.setFieldName("accountName");
        elemField.setXmlName(new javax.xml.namespace.QName("http://microsoft.com/webservices/SharePointPortalServer/UserProfileService", "accountName"));
        elemField.setXmlType(new javax.xml.namespace.QName("http://www.w3.org/2001/XMLSchema", "string"));
        elemField.setMinOccurs(0);
        elemField.setNillable(false);
        typeDesc.addFieldDesc(elemField);
        elemField = new org.apache.axis.description.ElementDesc();
        elemField.setFieldName("sourceInternal");
        elemField.setXmlName(new javax.xml.namespace.QName("http://microsoft.com/webservices/SharePointPortalServer/UserProfileService", "sourceInternal"));
        elemField.setXmlType(new javax.xml.namespace.QName("http://www.w3.org/2001/XMLSchema", "string"));
        elemField.setNillable(false);
        typeDesc.addFieldDesc(elemField);
        elemField = new org.apache.axis.description.ElementDesc();
        elemField.setFieldName("sourceReference");
        elemField.setXmlName(new javax.xml.namespace.QName("http://microsoft.com/webservices/SharePointPortalServer/UserProfileService", "sourceReference"));
        elemField.setXmlType(new javax.xml.namespace.QName("http://www.w3.org/2001/XMLSchema", "string"));
        elemField.setNillable(false);
        typeDesc.addFieldDesc(elemField);
        elemField = new org.apache.axis.description.ElementDesc();
        elemField.setFieldName("newPrivacy");
        elemField.setXmlName(new javax.xml.namespace.QName("http://microsoft.com/webservices/SharePointPortalServer/UserProfileService", "newPrivacy"));
        elemField.setXmlType(new javax.xml.namespace.QName("http://microsoft.com/webservices/SharePointPortalServer/UserProfileService", "Privacy"));
        elemField.setNillable(false);
        typeDesc.addFieldDesc(elemField);
    }

    /**
     * Return type metadata object
     */
    public static org.apache.axis.description.TypeDesc getTypeDesc() {
        return typeDesc;
    }

    /**
     * Get Custom Serializer
     */
    public static org.apache.axis.encoding.Serializer getSerializer(
           java.lang.String mechType,
           java.lang.Class _javaType,
           javax.xml.namespace.QName _xmlType) {
        return
          new  org.apache.axis.encoding.ser.BeanSerializer(
            _javaType, _xmlType, typeDesc);
    }

    /**
     * Get Custom Deserializer
     */
    public static org.apache.axis.encoding.Deserializer getDeserializer(
           java.lang.String mechType,
           java.lang.Class _javaType,
           javax.xml.namespace.QName _xmlType) {
        return
          new  org.apache.axis.encoding.ser.BeanDeserializer(
            _javaType, _xmlType, typeDesc);
    }

}