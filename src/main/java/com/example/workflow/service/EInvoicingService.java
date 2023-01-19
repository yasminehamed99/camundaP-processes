package com.example.workflow.service;

import camundajar.impl.com.google.gson.Gson;
import com.example.workflow.component.CertificateAuthResponse;
import com.example.workflow.dto.*;
import com.example.workflow.exceptions.CertificateAuthenticateException;
import com.example.workflow.exceptions.Process;
import com.example.workflow.exceptions.ProcessConfigException;
import com.example.workflow.exceptions.ProcessException;
import com.example.workflow.exceptions.ProcessManager;
import com.example.workflow.validation.ProcessInputImpl;
import com.example.workflow.validation.ValidationResults;
import com.example.workflow.validation.ValidationResultsImpl;
import com.example.workflow.validation.ValidationStatus;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.owlike.genson.Genson;
import org.apache.commons.lang3.StringUtils;
import org.camunda.bpm.engine.HistoryService;
import org.camunda.bpm.engine.history.HistoricVariableInstance;
import org.camunda.connect.Connectors;
import org.camunda.connect.httpclient.HttpConnector;
import org.camunda.connect.httpclient.HttpRequest;
import org.camunda.connect.httpclient.HttpResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@Service
public class EInvoicingService {



    private ProcessManager<String> processManager=new ProcessManager<String>() {
        @Override
        public Process<String> getProcess(int processId) throws ProcessConfigException {
            return null;
        }

        @Override
        public Process<String> buildProcess(int processId) throws ProcessConfigException {
            return null;
        }
    };

    @Value("2")
    private Integer clearanceProcessId;
    @Value("1")
    private Integer reportingProcessId;

    @Value("${compliance.checks.url}")
    private String complianceChecksUrl;

    private Process<String> clearanceProcess;
    private Process<String> reportingProcess;

    @Autowired
    private Path xsdFile;

@Autowired
    private Path enRulesFile;
@Autowired

    private Path ksaRulesFile;

    @Value("${zatca.signing.certificate}")
    private String zatcaSigningCertificate;

    @Value("${zatca.signing.private.key}")
    private String zatcaSigningPrivateKey;

@Autowired
    private RestTemplate restTemplate;
    private final HistoryService historyService;


    @Value(value = " http://localhost:8012/core/auth/")
    private String v2CertificateAuthenticationURL;

    @Value(value = " http://localhost:8012/core/auth/")
    private String v1CertificateAuthenticationURL;
@Autowired
    public EInvoicingService(HistoryService historyService) {
        this.historyService = historyService;
    }

    @PostConstruct
    private void init() throws ProcessConfigException {
        clearanceProcess = processManager.getProcess(clearanceProcessId);
    }
    public EInvoicingReportingResult report(String invoice, String invoiceHash, String language, String authenticationCertificate, String uuid, CertificateAuthResponse certificateAuthResponse) throws ProcessException {

        try {
            reportingProcess = processManager.buildProcess(reportingProcessId);
        } catch (ProcessConfigException e) {
            throw new ProcessException(e.getMessage());
        }

        ProcessInputImpl input = new ProcessInputImpl();
        Map<String, Object> data = new HashMap<>();
        input.setData(data);
        data.put("INVOICE", invoice);
        data.put("INVOICE_HASH", invoiceHash);
        data.put("LANGUAGE", language);
        data.put("XSD_FILE", xsdFile);
        data.put("EN_RULES_FILE", enRulesFile);
        data.put("KSA_RULES_FILE", ksaRulesFile);
        data.put("PROCESSTYPE","REPORTING");
        data.put("REST_TEMPLATE", restTemplate);
        data.put("REQUEST_UUID",uuid);
        data.put("AUTHENTICATION_CERTIFICATE", authenticationCertificate);
        data.put("CERTIFICATE_AUTHENTICATION_RESPONSE", certificateAuthResponse);

        data.put("COMPLIANCE_CHECK_URL", complianceChecksUrl);

        ProcessOutput<String> output =  reportingProcess.process(input);

        ValidationResults validationResults = (ValidationResults) output.getArtifacts().get("VALIDATION_RESULTS");

        EInvoicingReportingResult eInvoicingResult = new EInvoicingReportingResult();
        if(ValidationStatus.ERROR.equals(validationResults.getStatus())) {
            eInvoicingResult.setReportingStatus(ReportingStatus.NOT_REPORTED);
        } else {
            eInvoicingResult.setReportingStatus(ReportingStatus.REPORTED);
        }
        eInvoicingResult.setValidationResults(validationResults);
        return eInvoicingResult;
    }

    public EInvoicingClearanceResult clear(String invoice, String invoiceHash, String language, String authenticationCertificate, String uuid, String certificateAuthResponse) throws ProcessException, JsonProcessingException {
        ObjectWriter objectWriter = new ObjectMapper().writer().withDefaultPrettyPrinter();
        Certificate certificate = new Certificate();
//        EInvoicingClearanceResult eInvoicingResult=new EInvoicingClearanceResult();

        certificate.setType("String");
        certificate.setValue(authenticationCertificate);
        Path xpath = Paths.get("src/main/resources/core/xsd/UBL-Invoice-2.1.xsd");
        XsdFile xsdFile = new XsdFile(xpath.toString(), "String");
        Invoice inv = new Invoice(invoice, "String");

        Language lang = new Language(language, "String");
        Path schematronPath = Paths.get("src/main/resources/core/en/CEN-EN16931-UBL.xsl");
        EnRules enRules = new EnRules(schematronPath.toString(), "String");
        Authentication authentication = new Authentication("authorization", "String");
        AuthenticationResponse authenticationResponse = new AuthenticationResponse("certificateAuthResponse", "String");
        BusinessRules businessRules = new BusinessRules("EN_16931", "String");
        ValidationResult validationResult =new ValidationResult("a","String");

        Variables variables = new Variables(certificate, xsdFile, inv, lang, enRules, authentication, authenticationResponse, businessRules,validationResult);
        Root root = new Root(variables);
        String requestBody = objectWriter.writeValueAsString(root);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Root> entity = new HttpEntity<Root>(root,headers);
        RestTemplate restTemplate=new RestTemplate();
        String url
                = "http://localhost:8080/engine-rest/process-definition/key/Process_1uq3zpi/start";
        ResponseEntity<String> personResultAsJsonStr = restTemplate.postForEntity(url, entity, String.class);

//        HttpConnector http = Connectors.getConnector(HttpConnector.ID);
//        HttpRequest request = http.createRequest();
//        request.post()
//                .url("https://camunda.agiletz.com/engine-rest/process-definition/key/Process_1uq3zpi/start")
//                .payload(requestBody)
//                .header("Content-Type", "application/json");
//        HttpResponse httpResponse = request.execute();


        Gson g = new Gson();
        ResonseData s = g.fromJson(personResultAsJsonStr.getBody(), ResonseData.class);
        System.out.println(s.id);
        List<HistoricVariableInstance> historicVariableInstances = historyService.createHistoricVariableInstanceQuery().processInstanceId(s.getId()).list();

        Genson genson = new Genson.Builder().useClassMetadata(true).create();
        ValidationResults validationResults= genson.deserialize((String) historicVariableInstances.get(2).getValue(), ValidationResults.class);
        EInvoicingClearanceResult eInvoicingResult = new EInvoicingClearanceResult();
        eInvoicingResult.setValidationResults(validationResults);
        if(ValidationStatus.ERROR.equals(eInvoicingResult.getValidationResults().getStatus())) {
            eInvoicingResult.setClearanceStatus(ClearanceStatus.NOT_CLEARED);
        } else {
            eInvoicingResult.setClearanceStatus(ClearanceStatus.CLEARED);
//
        }
        return eInvoicingResult;


//        return httpResponse;
    }

    public AbstractMap.SimpleEntry<String, CertificateAuthResponse> authenticateV2(String authentication) {

        if (StringUtils.isBlank(authentication) || !authentication.startsWith("Basic")) {
            return null;
        }
        String auth = authentication.replace("Basic", "").trim();
        try {
            String[] authParts = new String(Base64.getDecoder().decode(auth)).split(":");

            String username = authParts[0];
            String password = authParts[1];

            ResponseEntity<CertificateAuthResponse> certificateAuthResponseEntity = restTemplate.postForEntity(v2CertificateAuthenticationURL, new ZatcaCSIDAuthRequest(username, password), CertificateAuthResponse.class);
            CertificateAuthResponse certificateAuthResponse = certificateAuthResponseEntity.getBody();
            if (AuthStatus.AUTHORIZED.equals(certificateAuthResponse.getAuthStatus()) && CertificateType.PRODUCTION.equals(certificateAuthResponse.getCertificateType())) {
                return new HashMap.SimpleEntry<>(username, certificateAuthResponse);
            }
            return null;
        } catch (Exception ex) {
            return null;
        }
    }

    public CertificateAuthResponse authenticate(String authenticationCertificate) {
        if (StringUtils.isNotBlank(authenticationCertificate)) {
            try {
                ZatcaProductionCSIDAuthRequest zatcaProductionCSIDAuthRequest = new ZatcaProductionCSIDAuthRequest();
                zatcaProductionCSIDAuthRequest.setCertificateEncodedBase64(authenticationCertificate);
                ResponseEntity<CertificateAuthResponse> certificateAuthResponseEntity = restTemplate.postForEntity(v1CertificateAuthenticationURL, zatcaProductionCSIDAuthRequest, CertificateAuthResponse.class);
                return certificateAuthResponseEntity.getBody();
            } catch (final HttpClientErrorException httpClientErrorException) {
                throw new CertificateAuthenticateException(new ErrorResponse("Invalid-Authenticate-Certificate", httpClientErrorException.getResponseBodyAsString()));
            } catch (HttpServerErrorException httpServerErrorException) {
                throw new CertificateAuthenticateException(new ErrorResponse("Invalid-Authenticate-Certificate", httpServerErrorException.getResponseBodyAsString()));
            } catch (Exception exception) {
                throw new CertificateAuthenticateException(new ErrorResponse("Invalid-Authenticate-Certificate", exception.getLocalizedMessage()));
            }
        }
        return null;
    }
}