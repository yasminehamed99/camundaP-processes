package com.example.workflow.controller;

import camundajar.impl.com.google.gson.Gson;
import com.example.workflow.component.CertificateAuthResponse;
import com.example.workflow.dto.*;
import com.example.workflow.exceptions.CustomVersionException;
import com.example.workflow.exceptions.ProcessException;
import com.example.workflow.service.EInvoicingService;
import com.example.workflow.validation.ValidationResults;
import com.example.workflow.validation.ValidationResultsImpl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import org.apache.commons.lang3.StringUtils;
import org.camunda.bpm.BpmPlatform;
import org.camunda.bpm.engine.HistoryService;
import org.camunda.bpm.engine.history.HistoricProcessInstance;
import org.camunda.bpm.engine.history.HistoricVariableInstance;
import org.camunda.connect.Connectors;
import org.camunda.connect.httpclient.HttpConnector;
import org.camunda.connect.httpclient.HttpRequest;
import org.camunda.connect.httpclient.HttpResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.AbstractMap;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static com.example.workflow.validation.ValidationMessageType.ERROR;
import static com.example.workflow.validation.ValidationMessageType.WARNING;
import static org.camunda.bpm.engine.variable.Variables.SerializationDataFormats.JSON;


@RestController
public class EiInvoicingController {
    @Autowired
    private EInvoicingService eInvoicingService;

    private final HistoryService historyService;

    @Autowired
    public EiInvoicingController(HistoryService historyService) {
        this.historyService = historyService;
    }


    @PostMapping(value = "/clearence")
    public ResponseEntity<EInvoicingClearanceResult> clear(@RequestBody ReportingRequestBodyDTO body,
                                                           @RequestHeader(value = "Accept-Language", required = false) String language,
                                                           @RequestHeader(value = "Authorization", required = false) String authorization,
                                                           @RequestHeader(value = "Accept-Version", required = false) String acceptedVersion) throws IOException, ProcessException {


//        try {
//            //check request
//            boolean isAPIV2 = false;
//            if (StringUtils.isNotBlank(acceptedVersion) && acceptedVersion.equalsIgnoreCase("V2")) {
//                isAPIV2 = true;
//
//            } else {
//                throw new CustomVersionException("This Version is not supported or not provided in the header.");
//            }
//            EInvoicingClearanceResult eInvoicingResult = validateRequest(body, language, isAPIV2);
//            if (ClearanceStatus.NOT_CLEARED.equals(eInvoicingResult.getClearanceStatus())) {
//                return new ResponseEntity<>(eInvoicingResult, HttpStatus.BAD_REQUEST);
//            }
        //start process
        try {
            EInvoicingClearanceResult eInvoicingResult = eInvoicingService.clear(body.getInvoice(), body.getInvoiceHash(), language, "valid", body.getUuid(), "certificateAuthResponse");
            if (ERROR.equals(eInvoicingResult.getValidationResults().getStatus())) {
                return new ResponseEntity<>(eInvoicingResult, HttpStatus.BAD_REQUEST);
            }
            if (WARNING.equals(eInvoicingResult.getValidationResults().getStatus())) {
                return new ResponseEntity<>(eInvoicingResult, HttpStatus.ACCEPTED);
            }
            return new ResponseEntity<>(eInvoicingResult, HttpStatus.OK);
        } catch (ProcessException processException) {
            EInvoicingClearanceResult eInvoicingResult = new EInvoicingClearanceResult();
            ValidationResultsImpl validationResultsImpl = new ValidationResultsImpl();
            validationResultsImpl.addErrorMessage(processException.getCategory(), processException.getCode(), processException.getMessage());
            eInvoicingResult.setValidationResults(validationResultsImpl);
            eInvoicingResult.setClearanceStatus(ClearanceStatus.NOT_CLEARED);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(eInvoicingResult);
        }
    }


//        return httpResponse;

//

//
//        ObjectWriter objectWriter = new ObjectMapper().writer().withDefaultPrettyPrinter();
//        Certificate certificate = new Certificate();
////        EInvoicingClearanceResult eInvoicingResult=new EInvoicingClearanceResult();
//
//        certificate.setType("String");
//        certificate.setValue("valid");
//        Path xpath = Paths.get("src/main/resources/core/xsd/UBL-Invoice-2.1.xsd");
//        XsdFile xsdFile = new XsdFile(xpath.toString(), "String");
//        Invoice invoice = new Invoice(body.getInvoice(), "String");
//
//        Language lang = new Language("ar", "String");
//        Path schematronPath = Paths.get("src/main/resources/core/en/CEN-EN16931-UBL.xsl");
//        EnRules enRules = new EnRules(schematronPath.toString(), "String");
//        Authentication authentication = new Authentication("authorization", "String");
//        AuthenticationResponse authenticationResponse = new AuthenticationResponse("AuthanticationResponse", "String");
//        BusinessRules businessRules = new BusinessRules("EN_16931", "String");
//        ValidationStatus validationStatus = new ValidationStatus("", "String");
//
//        Variables variables = new Variables(certificate, xsdFile, invoice, lang, enRules, authentication, authenticationResponse, businessRules, validationStatus);
//        Root root = new Root(variables);
//        String requestBody = objectWriter.writeValueAsString(root);
//        HttpConnector http = Connectors.getConnector(HttpConnector.ID);
//        HttpRequest request = http.createRequest();
//        request.post()
//                .url("http://localhost:8080/engine-rest/process-definition/key/Process_1uq3zpi/start")
//                .payload(requestBody)
//                .header("Content-Type", "application/json");
//        HttpResponse httpResponse = request.execute();
//        Gson g = new Gson();
//        ResonseData s = g.fromJson(httpResponse.getResponse(), ResonseData.class);
//        List<HistoricVariableInstance> historicVariableInstances = historyService.createHistoricVariableInstanceQuery().processInstanceId(s.getId()).list();
//        System.out.println(historicVariableInstances.get(6).getName() + " " + historicVariableInstances.get(6).getValue());
//        ValidationResults validationResults = (ValidationResults)historicVariableInstances.get(6).getValue();
////        String clearedInvoice = (String) output.getArtifacts().get("CLEARED_INVOICE");
//
//
//        eInvoicingResult.setValidationResults(validationResults);
////        if(ERROR.equals(validationResults.getStatus())) {
////            eInvoicingResult.setClearanceStatus(ClearanceStatus.NOT_CLEARED);
////        }
////
////         else {
////            eInvoicingResult.setClearanceStatus(ClearanceStatus.CLEARED);
//////            eInvoicingResult.setClearedInvoice(clearedInvoice);
////        }
//
//
////        return httpResponse;
//        if (ERROR.equals(eInvoicingResult.getValidationResults().getStatus())) {
//            return new ResponseEntity<>(eInvoicingResult, HttpStatus.BAD_REQUEST);
//        }
//        if (WARNING.equals(eInvoicingResult.getValidationResults().getStatus())) {
//            return new ResponseEntity<>(eInvoicingResult, HttpStatus.ACCEPTED);
//        }
//        return new ResponseEntity<>(eInvoicingResult, HttpStatus.OK);
////        catch (ProcessException processException)
////        {
////            EInvoicingClearanceResult eInvoicingResult = new EInvoicingClearanceResult();
////            ValidationResultsImpl validationResultsImpl = new ValidationResultsImpl();
////            validationResultsImpl.addErrorMessage(processException.getCategory(), processException.getCode(), processException.getMessage());
////            eInvoicingResult.setValidationResults(validationResultsImpl);
////            eInvoicingResult.setClearanceStatus(ClearanceStatus.NOT_CLEARED);
////            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(eInvoicingResult);
////        }

    @PostMapping(value = "/reporting")
    public ResponseEntity<EInvoicingReportingResult> report(@RequestBody ReportingRequestBodyDTO body,
                                                            @RequestHeader("Accept-Language") String language,
                                                            @RequestHeader (value = "A uthorization", required = false) String authorization,
                                                            @RequestHeader (value = "Accept-Version", required = false) String acceptedVersion) throws ProcessException {
        try {
            CertificateAuthResponse certificateAuthResponse;
            String authenticationCertificate = null;
            boolean isAPIV2 = false;
            if(StringUtils.isNotBlank(acceptedVersion) && acceptedVersion.equalsIgnoreCase("V2")) {
                isAPIV2 = true;
                AbstractMap.SimpleEntry<String, CertificateAuthResponse> certificateAuthResponseMapEntry = eInvoicingService.authenticateV2(authorization);
                if(certificateAuthResponseMapEntry == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
                } else {
                    authenticationCertificate = certificateAuthResponseMapEntry.getKey();
                    certificateAuthResponse = certificateAuthResponseMapEntry.getValue();
                }
            } else {
                throw new CustomVersionException("This Version is not supporte                                                                                      d or not provided in the header.");
            }

            EInvoicingReportingResult eInvoicingResult = validateReportRequest(body, language, isAPIV2);

            if(ReportingStatus.NOT_REPORTED.equals(eInvoicingResult.getReportingStatus())) {
                return new ResponseEntity<>(eInvoicingResult, HttpStatus.BAD_REQUEST);
            }

            eInvoicingResult = eInvoicingService.report(body.getInvoice(), body.getInvoiceHash(), language, authenticationCertificate, body.getUuid(), certificateAuthResponse);
            if (ERROR.equals(eInvoicingResult.getValidationResults().getStatus())) {
                return new ResponseEntity<>(eInvoicingResult, HttpStatus.BAD_REQUEST);
            }
            if (WARNING.equals(eInvoicingResult.getValidationResults().getStatus())) {
                return new ResponseEntity<>(eInvoicingResult, HttpStatus.ACCEPTED);
            }
            return new ResponseEntity<>(eInvoicingResult, HttpStatus.OK);
        }
        catch (ProcessException processException)
        {
            EInvoicingReportingResult eInvoicingResult = new EInvoicingReportingResult();
            ValidationResultsImpl validationResultsImpl = new ValidationResultsImpl();
            validationResultsImpl.addErrorMessage(processException.getCategory(), processException.getCode(), processException.getMessage());
            eInvoicingResult.setValidationResults(validationResultsImpl);
            eInvoicingResult.setReportingStatus(ReportingStatus.NOT_REPORTED);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(eInvoicingResult);
        }
    }


    private void uuidValidation(ReportingRequestBodyDTO body, ValidationResultsImpl validationResults) {
        if(body.getUuid() == null || body.getUuid().isBlank()) {
            validationResults.addErrorMessage("UUID-Errors", "Invalid-UUID", "UUID is not present in the API body");
        } else {
            try {
                UUID.fromString(body.getUuid());
            } catch (IllegalArgumentException exception){
                validationResults.addErrorMessage("UUID-Errors", "Invalid-UUID", "UUID format in the API body is not valid");
            }
        }
    }
    private EInvoicingReportingResult validateReportRequest(ReportingRequestBodyDTO body, String authenticationCertificate,  boolean isAPIV2) {
        EInvoicingReportingResult eInvoicingResult = new EInvoicingReportingResult();

        ValidationResultsImpl validationResults = new ValidationResultsImpl();
        productionCSIDValidation(authenticationCertificate, isAPIV2, validationResults);

        documentValidation(body, validationResults);

        uuidValidation(body, validationResults);

        if(validationResults.getErrorMessages() != null && !validationResults.getErrorMessages().isEmpty()) {
            eInvoicingResult.setReportingStatus(ReportingStatus.NOT_REPORTED);
            eInvoicingResult.setValidationResults(validationResults);
        }

        return eInvoicingResult;
    }
    private EInvoicingClearanceResult validateRequest(ReportingRequestBodyDTO body, String authenticationCertificate, boolean isAPIV2) {
        EInvoicingClearanceResult eInvoicingResult = new EInvoicingClearanceResult();

        ValidationResultsImpl validationResults = new ValidationResultsImpl();
        productionCSIDValidation(authenticationCertificate, isAPIV2, validationResults);

        documentValidation(body, validationResults);

        uuidValidation(body, validationResults);

        if(validationResults.getErrorMessages() != null  && !validationResults.getErrorMessages().isEmpty()) {
            eInvoicingResult.setClearanceStatus(ClearanceStatus.NOT_CLEARED);
            eInvoicingResult.setValidationResults(validationResults);
        }

        return eInvoicingResult;
    }
    private void documentValidation(ReportingRequestBodyDTO body, ValidationResultsImpl validationResults) {
        if(body.getInvoiceHash() == null || body.getInvoiceHash().isBlank()) {
            validationResults.addErrorMessage("InvoiceHash-Errors", "Invalid-InvoiceHash", "Document hash is not present in the API body");
        } else {
            try {
                Base64.getDecoder().decode(body.getInvoiceHash());
            } catch (Exception exception){
                validationResults.addErrorMessage("InvoiceHash-Errors", "Invalid-InvoiceHash", "Document hash format in the API body is not valid");
            }
        }
    }
    private void productionCSIDValidation(String authenticationCertificate, boolean isAPIV2, ValidationResultsImpl validationResults) {

        if (!isAPIV2 && authenticationCertificate == null || authenticationCertificate.isBlank()) {
            validationResults.addErrorMessage("Authentication-Errors", "Invalid-Authentication-Certificate", "Production CSID is not present in the API header");
        }
    }

}
