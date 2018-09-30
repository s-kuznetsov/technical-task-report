package com.atlassian.plugins.tutorial.jira.reports;

import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.datetime.DateTimeFormatter;
import com.atlassian.jira.datetime.DateTimeFormatterFactory;
import com.atlassian.jira.datetime.DateTimeStyle;
import com.atlassian.jira.issue.search.SearchException;
import com.atlassian.jira.issue.search.SearchProvider;
import com.atlassian.jira.issue.search.SearchResults;
import com.atlassian.jira.jql.builder.JqlQueryBuilder;
import com.atlassian.jira.plugin.report.impl.AbstractReport;
import com.atlassian.jira.project.Project;
import com.atlassian.jira.project.ProjectManager;
import com.atlassian.jira.security.roles.ProjectRole;
import com.atlassian.jira.security.roles.ProjectRoleManager;
import com.atlassian.jira.user.ApplicationUser;
import com.atlassian.jira.user.UserHistoryItem;
import com.atlassian.jira.user.UserProjectHistoryManager;
import com.atlassian.jira.util.ParameterUtils;
import com.atlassian.jira.web.FieldVisibilityManager;
import com.atlassian.jira.web.action.ProjectActionSupport;
import com.atlassian.jira.web.bean.PagerFilter;
import com.atlassian.plugin.spring.scanner.annotation.component.Scanned;
import com.atlassian.plugin.spring.scanner.annotation.imports.JiraImport;
import com.atlassian.query.Query;
import com.atlassian.query.QueryImpl;
import com.google.common.collect.ImmutableMap;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;

import webwork.action.ServletActionContext;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Scanned
public class ReportExtended extends AbstractReport {
    private static final Logger log = Logger.getLogger(ReportExtended.class);

    @JiraImport
    private final SearchProvider searchProvider;
    @JiraImport
    private final FieldVisibilityManager fieldVisibilityManager;
    @JiraImport
    private final ProjectManager projectManager;
    @JiraImport
    private final ProjectRoleManager projectRoleManager;
    @JiraImport
    private final UserProjectHistoryManager projectHistoryManager;
    private final DateTimeFormatter formatter;

    public ReportExtended(final SearchProvider searchProvider,
                          final FieldVisibilityManager fieldVisibilityManager,
                          final ProjectManager projectManager,
                          final ProjectRoleManager projectRoleManager,
                          final UserProjectHistoryManager projectHistoryManager,
                          @JiraImport DateTimeFormatterFactory dateTimeFormatterFactory) {
        this.searchProvider = searchProvider;
        this.fieldVisibilityManager = fieldVisibilityManager;
        this.projectManager = projectManager;
        this.projectRoleManager = projectRoleManager;
        this.projectHistoryManager = projectHistoryManager;
        this.formatter = dateTimeFormatterFactory.formatter().withStyle(DateTimeStyle.DATE).forLoggedInUser();
    }

    public SearchResults getResults(Query query, ApplicationUser user) {
        try {
            SearchResults searchResults = searchProvider.search(query, user, PagerFilter.getUnlimitedFilter());
            return searchResults;
        } catch (SearchException e) {
            log.error("Exception rendering " + this.getClass().getName() + ".  Exception \n" + Arrays.toString(e.getStackTrace()));
            return null;
        }
    }

    public String generateReportHtml(ProjectActionSupport action, Map params) throws Exception {
        String selectedProjectId = (String) params.get("selectedProjectId");
        String selectedDue = (String) params.get("selectedDueDate");

        Date selectedDueDate;
        if (StringUtils.isEmpty(selectedDue)) {
            DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd");
            String now = dateFormat.format(new Date());
            selectedDueDate = dateFormat.parse(now);
        } else {
            selectedDueDate = formatter.parse(ParameterUtils.getStringParam(params, "selectedDueDate"));
        }

        final Query query = new QueryImpl(JqlQueryBuilder.newClauseBuilder().project(selectedProjectId).and().due().lt(selectedDueDate).buildClause());

        final Map startingParams = ImmutableMap.builder()
                .put("action", action)
                .put("searchResults", getResults(query, action.getLoggedInUser()))
                .put("fieldVisibility", fieldVisibilityManager)
                .put("formatter", formatter).build();

        return descriptor.getHtml("view", startingParams);
    }

    public void validate(ProjectActionSupport action, Map params) {
        String selectedDue = (String) params.get("selectedDueDate");
        if (!StringUtils.isEmpty(selectedDue)) {
            try {
                formatter.parse(ParameterUtils.getStringParam(params, "selectedDueDate"));
            } catch (IllegalArgumentException e) {
                action.addError("selectedDueDate", action.getText("report.issuecreation.duedate.required"));
                log.error("Exception while parsing selectedDueDate");
            }
        }
    }

    @Override
    public boolean showReport() {
        ApplicationUser loggedInUser = ComponentAccessor.getJiraAuthenticationContext().getLoggedInUser();
        Project projectObj = projectManager.getProjectObjByKey(getCurrentProjectKey());
        ProjectRole projectRole = projectRoleManager.getProjectRole("Project-manager");
        return projectRoleManager.isUserInProjectRole(loggedInUser, projectRole, projectObj);
    }

    private String getCurrentProjectKey() {
        HttpServletRequest request = ServletActionContext.getRequest();
        if (request != null) {
            Pattern r = Pattern.compile("/projects/([A-Z]+)");
            Matcher m = r.matcher(request.getRequestURI());
            if (m.find())
                return m.group(1);
            else {
                ApplicationUser loggedInUser = ComponentAccessor.getJiraAuthenticationContext().getLoggedInUser();
                List<UserHistoryItem> historyList = projectHistoryManager.getProjectHistoryWithoutPermissionChecks(loggedInUser);
                if (historyList.size() > 0) {
                    Project currentProject = ComponentAccessor.getProjectManager().getProjectObj(Long.parseLong(historyList.get(0).getEntityId()));
                    if (currentProject != null)
                        return currentProject.getKey();
                }
            }
        }
        return null;
    }
}