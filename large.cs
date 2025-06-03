using CAAPS.Enums;
using CAAPS.Swift.MT564;
using CAAPS.SwiftDbHandler;
using Caaps_Models.Display;
using Caaps_Models.Notifications;
using CaapsWebServer.AccessLayer.Implementation;
using CaapsWebServer.AccessLayer.Interfaces;
using CaapsWebServer.Config;
using CaapsWebServer.DataLayer.DataModel;
using CaapsWebServer.DataLayer.Interfaces;
using CaapsWebServer.Enums;
using CaapsWebServer.Models.Generic;
using CaapsWebServer.Models.Response;
using CaapsWebServer.Solace;
using LogUtility.Logger;
using Microsoft.Extensions.Options;
using MoreLinq.Extensions;
using System;
using System.Collections.Generic;
using System.Dynamic;
using Caaps_Models.Solace;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using System.Text.Json;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using CaapsWebServer.Utilities;
using CAAPS;
using Microsoft.Extensions.Configuration;
using CAAPS.Common.Security;
using System.Text.RegularExpressions;
//using CAAPS.SwiftDb.Common.Security;
using System.Collections.ObjectModel;
using CaapsWebServer.Models.Request;
using Newtonsoft.Json.Linq;
using LinqToDB.Common;


namespace CaapsWebServer.DataLayer.Implementation
{
    public class EventDBHandler : IEventDBHandler
    {
        private readonly SwiftDbContextWeb swiftContext = null;
        private readonly CAAPSContext context = null;
        private readonly IEnumHelper enumHelper = null;
        private readonly LinqToDbHelper linqToDbHelper = null;

        private readonly CaapsLinqToDB.DBModels.LinqToDBSwiftContext linqToDBContext = null;

        private readonly DisplayServiceHelper displayDataHelper = null;

        private readonly DisplayToMt564 displayToMt = null;
        private readonly IAdvanceSearchService advanceSearchService = null;
        private readonly SolaceMessageListener solaceMessageListener = null;
        private readonly SolaceSettings solaceSettings;
        private readonly IAuditTrailOperationalDBHandler auditTrailDBHandler = null;
        private readonly AppNotificationSender appNotificationSender = null;
        private readonly IConfiguration configuration;

        public EventDBHandler(IConfiguration _configuration, SwiftDbContextWeb swiftContext, CAAPSContext context, IEnumHelper enumHelper, DisplayServiceHelper displayDataHelper, IAdvanceSearchService advanceSearchService, DisplayToMt564 displayToMt, SolaceMessageListener solaceMessageListener, IOptionsMonitor<SolaceSettings> solaceSettings, IAuditTrailOperationalDBHandler auditTrailDBHandler, LinqToDbHelper linqToDbHelper, CaapsLinqToDB.DBModels.LinqToDBSwiftContext linqToDBContext, AppNotificationSender appNotificationSender)
        {
            this.swiftContext = swiftContext;
            this.context = context;
            this.enumHelper = enumHelper;
            this.displayDataHelper = displayDataHelper;
            this.advanceSearchService = advanceSearchService;
            this.displayToMt = displayToMt;
            this.solaceMessageListener = solaceMessageListener;
            this.solaceSettings = solaceSettings.CurrentValue;
            this.auditTrailDBHandler = auditTrailDBHandler;
            this.linqToDbHelper = linqToDbHelper;
            this.linqToDBContext = linqToDBContext;
            this.appNotificationSender = appNotificationSender;
            this.configuration = _configuration;
        }

        public ResponseParent EventApprovalRejection(int goldenRecordId, int Status, string Role, ApproveReject detail)
        {
            ResponseParent res = new ResponseParent();
            try
            {
                Logger.Log("DisplayObject = " + JsonConvert.SerializeObject(detail.displayData), LogType.Debug);
                Logger.Log("ApproveReject detail: IsSuppressNotificationEnabled = " + detail.IsSuppressNotificationEnabled + ", Action: " + (detail.IsSuppressNotificationEnabled ? "Suppressing notifications" : "Notifications enabled"), LogType.Debug);
                if (Role != UserRoleConsts.SUPERVISOR && Role != UserRoleConsts.SYSTEM_ADMIN)
                {
                    res.IsSuccess = false;
                    res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NoPermission);
                    res.MessageId = (int)ResponseCodeMessage.NoPermission;
                }
                else
                {
                    GoldenRecordInternalChatDetail newComment = new GoldenRecordInternalChatDetail();
                    newComment.ChatText = detail.comment;
                    newComment.GoldenRecordId = goldenRecordId;
                    newComment.IsActive = 1;
                    newComment.OriginatedFromAction = detail.OriginatedFromAction;
                    newComment.EntryBy = detail.EntryBy;
                    newComment.EntryDtTime = DateTime.Now;
                    newComment.EntryDtTimeUtc = DateTime.UtcNow;
                    this.context.GoldenRecordInternalChatDetails.Add(newComment);
                    this.context.SaveChanges();

                    List<CaEventConflict> allConflicts = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == goldenRecordId).ToList();
                    GoldenRecordMst g = this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == goldenRecordId).FirstOrDefault();
                    CaapsLinqToDB.DBModels.MT564Message message = this.linqToDbHelper.GetEventDetailsByGolderRecordId((long)goldenRecordId);

                    GoldenRecordMst grm = this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == goldenRecordId).FirstOrDefault();
                    string[] GPDFields = new string[] { };
res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                    GPDFields = (from cg in this.context.CaEventConfigs
                                 join cem in this.context.CaEventTypeMsts on cg.CaEventTypeId equals cem.CaEventTypeId
                                 join ce in this.context.CaEventMsts on cg.CaEventMstId equals ce.CaEventMstId
                                 where ce.CaEventCode == grm.EventName && cem.CaEventType == grm.EventMvc
                                 select cg.GpdDateType).FirstOrDefault().Split(',');

                    if (GPDFields.Length == 1)
                    {
                        grm.GpdDateType = GPDFields[0];
                        this.context.GoldenRecordMsts.Update(grm);
                        this.context.SaveChanges();
                    }
                    else if (GPDFields.Length > 0)
                    {
                        string matchDateData = System.IO.File.ReadAllText("./MatchDates.json", Encoding.UTF8);
                        var dateField = System.Text.Json.JsonSerializer.Deserialize<List<MatchDateModel>>(matchDateData);
                        IDictionary<string, DateTime?> objGPDFieldsData = new Dictionary<string, DateTime?>();
                        for (int i = 0; i < GPDFields.Length; i++)
                        {
                            objGPDFieldsData.Add(
                                GPDFields[i],
                                detail.displayData.GetType().GetProperty(dateField.Where(x => x.Qualifier == GPDFields[i]).FirstOrDefault().MatchDate).GetValue(detail.displayData) == null ? null :
                                Convert.ToDateTime(detail.displayData.GetType().GetProperty(dateField.Where(x => x.Qualifier == GPDFields[i]).FirstOrDefault().MatchDate).GetValue(detail.displayData).ToString())
                                );
                        }

                        if (!objGPDFieldsData.Any(x => x.Value != null))
                        {
                            grm.GpdDateType = "NONE";
                        }
                        else if (objGPDFieldsData.Where(x => x.Value != null).Count() == 1)
                        {
                            grm.GpdDateType = objGPDFieldsData.Where(x => x.Value != null).FirstOrDefault().Key;
                        }
                        else if (objGPDFieldsData.Where(x => x.Value != null).Count() > 1)
                        {
                            grm.GpdDateType = objGPDFieldsData.Where(x => x.Value != null).OrderBy(x => x.Value).FirstOrDefault().Key;
                        }
                        this.context.GoldenRecordMsts.Update(grm);
                        this.context.SaveChanges();
                    }


                    if (Status == 1) //Approved
                    {
                        List<CaEventConflict> conflicts = allConflicts.Where(x => x.ReviewStatus == (int)EventReviewStatus.InReview).ToList();

                        if (g.GoldenRecordStatus == (string)EventWorkFlowStatus.PendingCancel)
                        {
                            if (g != null)
                            {
                                message.MessageData.GeneralInformation.FunctionOfMessage.Function = "CANC";
                                message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.COMP;
                                AdditionalInfoFlags flagDetails = this.linqToDbHelper.getAdditionFlags(message);
                                this.linqToDBContext.Update(message);
                                this.linqToDBContext.SaveChanges();
                                Logger.Log($"EventApprovalRejection EventWorkFlowStatus.Cancelled", LogType.Info);
                                g.GoldenRecordStatus = EventWorkFlowStatus.Cancelled;
                                g.ReviewByDate = null;
                                g.IsAdditionalTextUpdated = flagDetails.IsAdditionTextUpdated;
                                g.IsInformationConditionsUpdated = flagDetails.IsInformationConditionsUpdated;
                                g.IsInformationToComplyUpdated = flagDetails.IsInformationToComplyUpdated;
                                g.IsNarrativeVersionUpdated = flagDetails.IsNarrativeVersionUpdated;
                                g.IsTaxationConditionsUpdated = flagDetails.IsTaxationConditionUpdated;
                                g.EarlyResponseDeadlineDate = flagDetails.EarlyResponseDeadline;
                                g.ProtectDate = flagDetails.ProtectDate;
                                g.ResponseDeadlineDate = flagDetails.ResponseDeadline;
                                g.MarketDeadlineDate = flagDetails.MarketDeadline;
                                g.IsoChangeType = flagDetails.ISOChangeType;
                                g.IsoEffectiveDate = flagDetails.ISOEffectiveDate;
                                g.IsoExDividendOrDistributionDate = flagDetails.ISOExDividendDate;
                                g.IsoExpiryDate = flagDetails.ISOExpiryDate;
                                g.IsoOfferor = flagDetails.ISOOfferor;
                                g.IsoRecordDate = flagDetails.ISORecordDate;
                                g.IsTouched = true;
                                g.IsAutoStp = false;
                                g.EntryDtTime = DateTime.Now;
                                g.EntryDtTimeUtc = DateTime.UtcNow;
                                g.EntryBy = detail.EntryBy;
                                this.context.SaveChanges();

                                this.SetResponseDeadlineDates(goldenRecordId, message, detail.EntryBy);

                                res.IsSuccess = true;
                                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                                res.MessageId = (int)ResponseCodeMessage.Successful;
                                /*
                                    As per CR#110 we dont need to send position notifications to client when Suppress Notification Enable check is false.
                                */
                                if (!detail.IsSuppressNotificationEnabled)
                                {
                                    ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                                    Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                                }
                            }
                            else
                            {
                                res.IsSuccess = false;
                                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NotFound);
                                res.MessageId = (int)ResponseCodeMessage.NotFound;
                            }
                        }
                        else if (g.GoldenRecordStatus == (string)EventWorkFlowStatus.PendingWithdraw)
                        {
                            if (g != null)
                            {
                                message.MessageData.GeneralInformation.FunctionOfMessage.Function = "WITH";
                                message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.COMP;
                                AdditionalInfoFlags flagDetails = this.linqToDbHelper.getAdditionFlags(message);
                                this.linqToDBContext.Update(message);
                                this.linqToDBContext.SaveChanges();
                                Logger.Log($"EventApprovalRejection EventWorkFlowStatus.Withdrawn", LogType.Info);
                                g.GoldenRecordStatus = EventWorkFlowStatus.Withdrawn;
                                g.IsAdditionalTextUpdated = flagDetails.IsAdditionTextUpdated;
                                g.IsInformationConditionsUpdated = flagDetails.IsInformationConditionsUpdated;
                                g.IsInformationToComplyUpdated = flagDetails.IsInformationToComplyUpdated;
                                g.IsNarrativeVersionUpdated = flagDetails.IsNarrativeVersionUpdated;
                                g.IsTaxationConditionsUpdated = flagDetails.IsTaxationConditionUpdated;
                                g.IsTouched = true;
                                g.EarlyResponseDeadlineDate = flagDetails.EarlyResponseDeadline;
                                g.ProtectDate = flagDetails.ProtectDate;
                                g.ResponseDeadlineDate = flagDetails.ResponseDeadline;
                                g.MarketDeadlineDate = flagDetails.MarketDeadline;
                                g.IsoChangeType = flagDetails.ISOChangeType;
                                g.IsoEffectiveDate = flagDetails.ISOEffectiveDate;
                                g.IsoExDividendOrDistributionDate = flagDetails.ISOExDividendDate;
                                g.IsoExpiryDate = flagDetails.ISOExpiryDate;
                                g.IsoOfferor = flagDetails.ISOOfferor;
                                g.IsoRecordDate = flagDetails.ISORecordDate;
                                g.ReviewByDate = null;
                                g.IsAutoStp = false;
                                g.EntryDtTime = DateTime.Now;
                                g.EntryDtTimeUtc = DateTime.UtcNow;
                                g.EntryBy = detail.EntryBy;
                                this.context.SaveChanges();
                                this.SetResponseDeadlineDates(goldenRecordId, message, detail.EntryBy);
                                res.IsSuccess = true;
                                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                                res.MessageId = (int)ResponseCodeMessage.Successful;
                                /*
                                    As per CR#110 we dont need to send position notifications to client when Suppress Notification Enable check is false.
                                */
                                if (!detail.IsSuppressNotificationEnabled)
                                {
                                    ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                                    Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                                }
                            }
                            elseprivate ResponseParent HandleException(Exception ex, ApproveReject detail, int goldenRecordId, int status, string role)
{
    var res = new ResponseParent
    {
        IsSuccess = false,
        Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError),
        MessageId = (int)ResponseCodeMessage.InternalServerError
    };

    dynamic logs = new ExpandoObject();
    logs.Data = JsonConvert.SerializeObject(detail);
    logs.StackTrace = ex.StackTrace;
    logs.goldenId = goldenRecordId;
    logs.status = status;
    logs.role = role;
    Logger.LogException(ex, LogType.Error, logs);
    this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
    return res;
}


// Usage
catch (Exception ex)
{
    return HandleException(ex, detail, goldenRecordId, Status, Role);
}
                            {
                                res.IsSuccess = false;
                                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NotFound);
                                res.MessageId = (int)ResponseCodeMessage.NotFound;
                            }
                        }
                        else if (g.GoldenRecordStatus == (string)EventWorkFlowStatus.PendingDelete)
                        {
                            DeleteEventModel model = new DeleteEventModel();
                            model.MessageFrom = Notification.Component.WEB_SERVER;
                            model.MessageAction = "DELETE_EVENT";
                            model.GoldenRecordId = goldenRecordId;
                            model.IsSuppressNotificationEnabled = detail.IsSuppressNotificationEnabled;
                            if (solaceSettings.SendToTopic)
                            {
                                this.solaceMessageListener.SendToTopic(solaceSettings.MatchingTopicName, JsonConvert.SerializeObject(model));
                            }
                            else
                            {
                                this.solaceMessageListener.SendToQueue(solaceSettings.MatchingQueueName, JsonConvert.SerializeObject(model));
                            }
                            res.IsSuccess = true;
                            res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                            res.MessageId = (int)ResponseCodeMessage.Successful;
                        }
                        else
                        {

                            conflicts.ForEach(conflict =>
                            {
                                conflict.FieldStatus = (byte)EventFieldStatus.Complete;
                                conflict.ReviewStatus = (byte)EventReviewStatus.UserResolved;
                                conflict.EntryBy = detail.EntryBy;
                                conflict.EntryDtTime = DateTime.Now;
                                conflict.EntryDtTimeUtc = DateTime.UtcNow;

                                if (conflict.FieldName.Contains("securityid"))
                                {
                                    GoldenRecordSecurityDetail existingObject = this.context.GoldenRecordSecurityDetails.Where(x => x.GoldenRecordId == conflict.GoldenRecordId
                                    && x.OptionNumber == conflict.OptionNumber
                                    && x.MovementId == conflict.MovementId).FirstOrDefault();
                                    var secIdType = detail.displayData.Options.Where(x =>
                                                    x.CaOptOptionNumber == conflict.OptionNumber)
                                                    .FirstOrDefault().securityMovement.Where(y =>
                                                        y.SMSecurityNumber == conflict.MovementId)
                                                    .FirstOrDefault().SMNewSecurityIDType;
                                    var secId = detail.displayData.Options.Where(x =>
                                                x.CaOptOptionNumber == conflict.OptionNumber)
                                                .FirstOrDefault().securityMovement.Where(y =>
                                                    y.SMSecurityNumber == conflict.MovementId)
                                                .FirstOrDefault().SMNewSecurityID;

                                    if (existingObject == null)
                                    {
                                        existingObject = new GoldenRecordSecurityDetail();
                                        existingObject.GoldenRecordId = conflict.GoldenRecordId;
                                        existingObject.OptionNumber = conflict.OptionNumber;
                                        existingObject.MovementId = conflict.MovementId;
                                        existingObject.CUSIP = secIdType == "CUSP" ? secId : "";
                                        existingObject.ISIN = secIdType == "ISIN" ? secId : "";
                                        existingObject.Sedol = secIdType == "Sedol" ? secId : "";
                                        existingObject.BloombergId = "";
                                        existingObject.ShortName = "";
                                        existingObject.LongName = "";
                                        existingObject.IsActive = 1;
                                        existingObject.EntryBy = detail.EntryBy;
                                        existingObject.EntryDtTime = DateTime.Now;
                                        existingObject.EntryDtTimeUtc = DateTime.UtcNow;
                                        this.context.GoldenRecordSecurityDetails.Add(existingObject);
                                    }
                                    else
                                    {
                                        if ((secIdType == "CUSP" && secId != existingObject.CUSIP)
                                        || (secIdType == "ISIN" && secId != existingObject.ISIN)
                                        || (secIdType == "Sedol" && secId != existingObject.Sedol)
                                        )
                                        {
                                            existingObject.CUSIP = secIdType == "CUSP" ? secId : "";
                                            existingObject.ISIN = secIdType == "ISIN" ? secId : "";
                                            existingObject.Sedol = secIdType == "Sedol" ? secId : "";
                                            existingObject.BloombergId = "";
                                            existingObject.ShortName = "";
                                            existingObject.LongName = "";
                                            this.context.GoldenRecordSecurityDetails.Update(existingObject);
                                        }
                                    }
                                    this.context.SaveChanges();
                                }

                                this.context.SaveChanges();
                            });

                            //getting null pointer exception from TransformDisplayToMt564 issue fix
                            CaapsLinqToDB.DBModels.MT564Message cloneMessage = JsonConvert.DeserializeObject<CaapsLinqToDB.DBModels.MT564Message>(JsonConvert.SerializeObject(message, Formatting.None, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }));
                            CaapsLinqToDB.DBModels.MT564Message UpdatedMessage = this.linqToDbHelper.TransformDisplayToMt564(message, detail.displayData);
                            UpdatedMessage.MessageData.GeneralInformation.FunctionOfMessage.Function = "REPL";
                            UpdatedMessage.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.COMP;

                            Boolean GPDUpdateOrNot = this.setGPDDate(cloneMessage, UpdatedMessage, detail.displayData.EventName, detail.displayData.EventMvc);
                            AdditionalInfoFlags flagDetails = this.linqToDbHelper.getAdditionFlags(UpdatedMessage);
                            Logger.Log("Updated MT564 Message = " + JsonConvert.SerializeObject(UpdatedMessage, Formatting.None, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }), LogType.Debug);

                            this.linqToDBContext.Update(UpdatedMessage);
                            this.linqToDBContext.SaveChanges();

                            if (g != null)
                            {
                                Logger.Log($"EventApprovalRejection EventWorkFlowStatus.Complete", LogType.Info);
                                g.GoldenRecordStatus = EventWorkFlowStatus.Complete;
                                g.IsAdditionalTextUpdated = flagDetails.IsAdditionTextUpdated;
                                g.IsInformationConditionsUpdated = flagDetails.IsInformationConditionsUpdated;
                                g.IsInformationToComplyUpdated = flagDetails.IsInformationToComplyUpdated;
                                g.IsNarrativeVersionUpdated = flagDetails.IsNarrativeVersionUpdated;
                                g.IsTaxationConditionsUpdated = flagDetails.IsTaxationConditionUpdated;
                                g.IsTouched = true;
                                g.EarlyResponseDeadlineDate = flagDetails.EarlyResponseDeadline;
                                g.ProtectDate = flagDetails.ProtectDate;
                                g.ResponseDeadlineDate = flagDetails.ResponseDeadline;
                                g.MarketDeadlineDate = flagDetails.MarketDeadline;
                                g.IsoChangeType = flagDetails.ISOChangeType;
                                g.IsoEffectiveDate = flagDetails.ISOEffectiveDate;
                                g.IsoExDividendOrDistributionDate = flagDetails.ISOExDividendDate;
                                g.IsoExpiryDate = flagDetails.ISOExpiryDate;
                                g.IsoOfferor = flagDetails.ISOOfferor;
                                g.IsoRecordDate = flagDetails.ISORecordDate;
                                g.ReviewByDate = null;
                                g.IsAutoStp = false;
                                g.EntryDtTime = DateTime.Now;
                                g.EntryDtTimeUtc = DateTime.UtcNow;
                                g.EntryBy = detail.EntryBy;
                                if (GPDUpdateOrNot == true)
                                {
                                    g.PositionFixDate = null;
                                    g.IsPositionCaptured = false;
                                    this.context.Database.ExecuteSqlRaw($"Exec Proc_Web_Submit_GoldenRecord_Position_Flag_Update_All_Related_Securities {goldenRecordId}");
                                }
                                this.context.SaveChanges();
                                this.SetResponseDeadlineDates(goldenRecordId, message, detail.EntryBy);
                                res.IsSuccess = true;
                                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                                res.MessageId = (int)ResponseCodeMessage.Successful;
                                /*
                                    As per CR#110 we dont need to send position notifications to client when Suppress Notification Enable check is false.
                                */
                                if (!detail.IsSuppressNotificationEnabled)
                                {
                                    ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, UpdatedMessage, g);
                                    Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                                }
                            }
                            else
                            {
                                res.IsSuccess = false;
                                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NotFound);
                                res.MessageId = (int)ResponseCodeMessage.NotFound;
                            }
                        }
                    }
                    else //Rejected
                    {
                        List<CaEventConflict> conflicts = allConflicts.Where(x => x.ReviewStatus == (int)EventReviewStatus.InReview).ToList();
                        conflicts.ForEach(conflict =>
                        {
                            conflict.ReviewStatus = (byte)EventReviewStatus.Open;
                            conflict.EntryDtTime = DateTime.Now;
                            conflict.EntryDtTimeUtc = DateTime.UtcNow;
                            this.context.SaveChanges();
                        });

                        if (g != null)
                        {
                            List<int> fieldStatus = allConflicts.Select(x => x.FieldStatus).ToList();
                            int finalStatus = fieldStatus.Max();
                            if (finalStatus == (int)EventFieldStatus.Incomplete)
                            {
                                Logger.Log($"EventApprovalRejection Rejected EventWorkFlowStatus.Incomplete", LogType.Info);
                                g.GoldenRecordStatus = EventWorkFlowStatus.Incomplete;
                                message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREU;
                            }
                            else if (finalStatus == (int)EventFieldStatus.Conflict)
                            {
                                Logger.Log($"EventApprovalRejection Rejected EventWorkFlowStatus.Conflict", LogType.Info);
                                g.GoldenRecordStatus = EventWorkFlowStatus.Conflict;
                                message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREU;
                            }
                            else if (finalStatus == (int)EventFieldStatus.Complete)
                            {
                                Logger.Log($"EventApprovalRejection Rejected EventWorkFlowStatus.Complete", LogType.Info);
                                g.GoldenRecordStatus = EventWorkFlowStatus.Complete;
                                message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREU;
                            }
                            else if (finalStatus == (int)EventFieldStatus.Updated)
                            {
                                Logger.Log($"EventApprovalRejection Rejected EventWorkFlowStatus.Updated", LogType.Info);
                                g.GoldenRecordStatus = EventWorkFlowStatus.Updated;
                                message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREU;
                            }
                            else
                            {
                                GoldenRecordMstAudit ga = this.context.GoldenRecordMstAudits.Where(x => x.GoldenRecordId == goldenRecordId).FirstOrDefault();
                                if (ga != null)
                                {
                                    g.GoldenRecordStatus = ga.GoldenRecordStatus;
                                    message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREU;
                                }
                            }
                            g.ReviewByDate = null;
                            g.IsAutoStp = false;
                            g.EntryBy = detail.EntryBy;
                            g.EntryDtTime = DateTime.Now;
                            g.EntryDtTimeUtc = DateTime.UtcNow;
                            this.context.SaveChanges();
                            this.linqToDBContext.Update(message);
                            this.linqToDBContext.SaveChanges();
                            res.IsSuccess = true;
                            res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                            res.MessageId = (int)ResponseCodeMessage.Successful;
                            /*
                                As per CR#110 we dont need to send position notifications to client in case of rejected.
                             */
                            //ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                            //Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                        }
                        else
                        {
                            res.IsSuccess = false;
                            res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NotFound);
                            res.MessageId = (int)ResponseCodeMessage.NotFound;
                        }
                    }



                }
                this.SaveInActiveDate(goldenRecordId);
                sendEventNotification(
                     $"Event approval perform",
                     "EVENT_APPROVAL",
                      new
                      {
                          GoldenId = goldenRecordId
                      });

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                res.IsSuccess = false;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                res.MessageId = (int)ResponseCodeMessage.InternalServerError;

                dynamic logs = new ExpandoObject();
                logs.Data = JsonConvert.SerializeObject(detail);
                logs.StackTrace = ex.StackTrace;
                logs.goldenId = goldenRecordId;
                logs.status = Status;
                logs.role = Role;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return res;
        }

        public WorkQueueResponse GetWorkQueueByUserId(int workQueueId, int userId)
        {
            WorkQueueResponse workQueueResponse = new WorkQueueResponse();
            try
            {
                if (userId > 0)
                {
                    workQueueResponse = (from wqm in this.context.WorkQueueMsts
                                         join wqum in this.context.WorkQueueUserMappings on wqm.WorkQueueId equals wqum.WorkQueueId
                                         where ((wqm.WorkQueueId == workQueueId) && (wqum.UserId == userId))
                                         select new WorkQueueResponse()
                                         {
                                             WorkQueueId = (int)wqm.WorkQueueId,
                                             WorkQueueName = wqm.WorkQueueName,
                                             WorkQueueObject = wqm.WorkQueueObject,
                                             EntryBy = wqm.EntryBy,
                                             EntryDtTime = wqm.EntryDtTime,
                                             EntryDtTimeUtc = wqm.EntryDtTimeUtc,
                                             IsActive = wqm.IsActive
                                         }).FirstOrDefault();
                }
                else
                {
                    workQueueResponse = (from wqm in this.context.WorkQueueMsts
                                         where ((wqm.WorkQueueId == workQueueId))
                                         select new WorkQueueResponse()
                                         {
                                             WorkQueueId = (int)wqm.WorkQueueId,
                                             WorkQueueName = wqm.WorkQueueName,
                                             WorkQueueObject = wqm.WorkQueueObject,
                                             EntryBy = wqm.EntryBy,
                                             EntryDtTime = wqm.EntryDtTime,
                                             EntryDtTimeUtc = wqm.EntryDtTimeUtc,
                                             IsActive = wqm.IsActive
                                         }).FirstOrDefault();
                }


                if (workQueueResponse != null)
                {
                    workQueueResponse.IsSuccess = true;
                    workQueueResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                    workQueueResponse.MessageId = (int)ResponseCodeMessage.Successful;
                }
                else
                {
                    workQueueResponse.IsSuccess = true;
                    workQueueResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NoRecord);
                    workQueueResponse.MessageId = (int)ResponseCodeMessage.NoRecord;
                }
            }
            catch (Exception ex)
            {
                workQueueResponse.IsSuccess = false;
                workQueueResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                workQueueResponse.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.workQueueId = workQueueId;
                logs.UserId = userId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return workQueueResponse;
        }


        public List<WorkQueueResponse> GetWorkQueuesByUserId(int userId)
        {
            List<WorkQueueResponse> workQueueResponses = new List<WorkQueueResponse>();
            try
            {
                if (userId > 0)
                {
                    workQueueResponses = (from wqm in this.context.WorkQueueMsts
                                          join wqum in this.context.WorkQueueUserMappings on wqm.WorkQueueId equals wqum.WorkQueueId
                                          where (wqum.UserId == userId)
                                          where (wqm.IsActive == 1)
                                          select new WorkQueueResponse()
                                          {
                                              WorkQueueId = (int)wqm.WorkQueueId,
                                              WorkQueueName = wqm.WorkQueueName,
                                              WorkQueueObject = wqm.WorkQueueObject,
                                              EntryBy = wqm.EntryBy,
                                              EntryDtTime = wqm.EntryDtTime,
                                              EntryDtTimeUtc = wqm.EntryDtTimeUtc,
                                              IsActive = wqm.IsActive
                                          }).ToList();

                }
                else
                {
                    workQueueResponses = (from wqm in this.context.WorkQueueMsts
                                          where (wqm.IsActive == 1)
                                          select new WorkQueueResponse()
                                          {
                                              WorkQueueId = (int)wqm.WorkQueueId,
                                              WorkQueueName = wqm.WorkQueueName,
                                              WorkQueueObject = wqm.WorkQueueObject,
                                              EntryBy = wqm.EntryBy,
                                              EntryDtTime = wqm.EntryDtTime,
                                              EntryDtTimeUtc = wqm.EntryDtTimeUtc,
                                              IsActive = wqm.IsActive
                                          }).ToList();
                }

            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return workQueueResponses;
        }
        public List<WorkQueueResponse> GetWorkQueuesByUserIdAndWqName(int userId, string name)
        {
            List<WorkQueueResponse> workQueueResponses = new List<WorkQueueResponse>();
            try
            {
                if (userId > 0)
                {
                    workQueueResponses = (from wqm in this.context.WorkQueueMsts
                                          join wqum in this.context.WorkQueueUserMappings on wqm.WorkQueueId equals wqum.WorkQueueId
                                          where (wqum.UserId == userId)
                                          where (wqm.IsActive == 1)
                                          where (wqm.WorkQueueName.ToLower() == name.ToLower())
                                          select new WorkQueueResponse()
                                          {
                                              WorkQueueId = (int)wqm.WorkQueueId,
                                              WorkQueueName = wqm.WorkQueueName,
                                              WorkQueueObject = wqm.WorkQueueObject,
                                              EntryBy = wqm.EntryBy,
                                              EntryDtTime = wqm.EntryDtTime,
                                              EntryDtTimeUtc = wqm.EntryDtTimeUtc,
                                              IsActive = wqm.IsActive
                                          }).ToList();

                }
                else
                {
                    workQueueResponses = (from wqm in this.context.WorkQueueMsts
                                          where (wqm.IsActive == 1)
                                          where (wqm.WorkQueueName.ToLower() == name.ToLower())
                                          select new WorkQueueResponse()
                                          {
                                              WorkQueueId = (int)wqm.WorkQueueId,
                                              WorkQueueName = wqm.WorkQueueName,
                                              WorkQueueObject = wqm.WorkQueueObject,
                                              EntryBy = wqm.EntryBy,
                                              EntryDtTime = wqm.EntryDtTime,
                                              EntryDtTimeUtc = wqm.EntryDtTimeUtc,
                                              IsActive = wqm.IsActive
                                          }).ToList();
                }

            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return workQueueResponses;
        }

        public List<CaEventConflict> GetEventConflictDetailsByGoldenId(int goldenId, int userId)
        {
            List<CaEventConflict> conflictDetails = new List<CaEventConflict>();
            GoldenRecordMst g = new GoldenRecordMst();
            try
            {
                conflictDetails = this.context.CaEventConflicts.Where(c => c.GoldenRecordId == goldenId).ToList();
                g = this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == goldenId).FirstOrDefault();
                if (!conflictDetails.Any(x => x.FieldName.Contains("letterofguaranteeddelivery")) && IsConditional(g))
                {
                    DisplayData displayData = this.linqToDbHelper.GetDisplayDataByGoldenRecordId((int)goldenId);
                    if (displayData.LetterofGuaranteedDelivery == null)
                    {
                        AllSourceResponse sources = GetAllSourceByGoldenId(goldenId);
                        CaEventConflict caEventConflict = new CaEventConflict();
                        caEventConflict.GoldenRecordId = displayData.CaapsId;
                        caEventConflict.FieldName = "eventdetail.letterofguaranteeddelivery.flag";
                        caEventConflict.OptionNumber = "";
                        caEventConflict.MovementId = "";
                        caEventConflict.ExistingSource = sources.Sources?.FirstOrDefault().EventSourceName;
                        caEventConflict.ClientValue = "";
                        caEventConflict.NewEventId = 0;
                        caEventConflict.NewEventSource = "";
                        caEventConflict.NewEventValue = "";
                        caEventConflict.NewEventOptionNumber = "";
                        caEventConflict.NewEventMovementId = "";
                        caEventConflict.IsActive = 1;
                        caEventConflict.EntryBy = userId;
                        caEventConflict.EntryDtTime = DateTime.Now;
                        caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                        caEventConflict.FieldStatus = 2;
                        caEventConflict.ReviewStatus = 1;
                        this.context.CaEventConflicts.Add(caEventConflict);
                        displayData.Options.ForEach(option =>
                        {
                            CaEventConflict CaOptCoverExpirationDate = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == goldenId && x.FieldName == "optiondetail.coverexpirationdate.cadatetime" && x.OptionNumber == option.CaOptOptionNumber).FirstOrDefault();
                            CaEventConflict CaOptDepositoryCoverExpirationDate = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == goldenId && x.FieldName == "optiondetail.depositorycoverexpirationdate.cadatetime" && x.OptionNumber == option.CaOptOptionNumber).FirstOrDefault();
                            CaOptCoverExpirationDate.FieldStatus = 0;
                            CaOptCoverExpirationDate.ReviewStatus = 3;
                            CaOptDepositoryCoverExpirationDate.FieldStatus = 0;
                            CaOptDepositoryCoverExpirationDate.ReviewStatus = 3;
                            this.context.CaEventConflicts.Update(CaOptCoverExpirationDate);
                            this.context.CaEventConflicts.Update(CaOptDepositoryCoverExpirationDate);
                            this.context.SaveChanges();
                        });
                        this.context.SaveChanges();
                        conflictDetails = this.context.CaEventConflicts.Where(c => c.GoldenRecordId == goldenId).ToList();
                    }

                    if (g.EventName == "OTHR" && g.EventMvc == "VOLU")
                    {
                        int totalOptions = displayData.Options.Count;
                        if (totalOptions > 0)
                        {
                            for (int i = 0; i < totalOptions; i++)
                            {
                                string currentOptionNumber = displayData.Options[i].CaOptOptionNumber;
                                if (currentOptionNumber != "999")
                                {
                                    if (!conflictDetails.Any(x => x.FieldName.Contains("optiondetail.coverexpirationdate.cadatetime") && x.OptionNumber == currentOptionNumber))
                                    {
                                        AllSourceResponse sources = GetAllSourceByGoldenId(goldenId);
                                        CaEventConflict caEventConflict = new CaEventConflict();
                                        caEventConflict.GoldenRecordId = displayData.CaapsId;
                                        caEventConflict.FieldName = "optiondetail.coverexpirationdate.cadatetime";
                                        caEventConflict.OptionNumber = "";
                                        caEventConflict.MovementId = "";
                                        caEventConflict.ExistingSource = sources.Sources?.FirstOrDefault().EventSourceName;
                                        caEventConflict.ClientValue = "";
                                        caEventConflict.NewEventId = 0;
                                        caEventConflict.NewEventSource = "";
                                        caEventConflict.NewEventValue = "";
                                        caEventConflict.NewEventOptionNumber = "";
                                        caEventConflict.NewEventMovementId = "";
                                        caEventConflict.IsActive = 1;
                                        caEventConflict.EntryBy = userId;
                                        caEventConflict.EntryDtTime = DateTime.Now;
                                        caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                                        caEventConflict.FieldStatus = (displayData.LetterofGuaranteedDelivery == "Y" ? 2 : 0);
                                        caEventConflict.ReviewStatus = 1;
                                        this.context.CaEventConflicts.Add(caEventConflict);
                                        this.context.SaveChanges();
                                        conflictDetails = this.context.CaEventConflicts.Where(c => c.GoldenRecordId == goldenId).ToList();
                                    }
                                }
                            }
                        }
                    }
                }
                conflictDetails = this.context.CaEventConflicts.Where(c => c.GoldenRecordId == goldenId).ToList();
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenId = goldenId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return conflictDetails;
        }

        public List<DisplayData> GetEventsForCounts(int userId, string title, string type)
        {
            List<WorkQueueMst> allWorkQueues = new List<WorkQueueMst>();

            if (userId > 0)
            {
                allWorkQueues = (from wqm in this.context.WorkQueueMsts
                                 join wqum in this.context.WorkQueueUserMappings on wqm.WorkQueueId equals wqum.WorkQueueId
                                 where ((wqum.UserId == userId) && wqm.IsActive == 1)
                                 select new WorkQueueMst()
                                 {
                                     WorkQueueId = (int)wqm.WorkQueueId,
                                     WorkQueueName = wqm.WorkQueueName,
                                     WorkQueueObject = wqm.WorkQueueObject,
                                     EntryBy = wqm.EntryBy,
                                     EntryDtTime = wqm.EntryDtTime,
                                     EntryDtTimeUtc = wqm.EntryDtTimeUtc,
                                     IsActive = wqm.IsActive
                                 }).ToList();
            }
            else
            {
                allWorkQueues = (from wqm in this.context.WorkQueueMsts
                                 where wqm.IsActive == 1
                                 select new WorkQueueMst()
                                 {
                                     WorkQueueId = (int)wqm.WorkQueueId,
                                     WorkQueueName = wqm.WorkQueueName,
                                     WorkQueueObject = wqm.WorkQueueObject,
                                     EntryBy = wqm.EntryBy,
                                     EntryDtTime = wqm.EntryDtTime,
                                     EntryDtTimeUtc = wqm.EntryDtTimeUtc,
                                     IsActive = wqm.IsActive
                                 }).ToList();
            }


            List<DisplayData> displayDatas = this.displayDataHelper.GetAllDisplayData(null, false);
            List<DisplayData> outDisplayData = new List<DisplayData>();
            allWorkQueues.ForEach(queue =>
            {
                try
                {
                    WorkQueueSearch workQueueObject = JsonConvert.DeserializeObject<WorkQueueSearch>(queue.WorkQueueObject);
                    IQueryable<DisplayData> tempDisplays = this.advanceSearchService.GetPredicate(displayDatas.AsQueryable(), workQueueObject);
                    if (tempDisplays is not null)
                    {
                        try
                        {
                            List<DisplayData> ds = tempDisplays.ToList();
                            foreach (var item in ds)
                            {
                                item.GroupName = queue.WorkQueueName;
                                outDisplayData.Add(item);
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.LogException(ex, LogType.Error, ex.StackTrace);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogException(ex, LogType.Error, ex.StackTrace);
                    this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
                }
            });

            if (outDisplayData.Count > 0)
            {
                outDisplayData = outDisplayData.Distinct().ToList();
                switch (type)
                {
                    case EventCountType.CRITICAL_COUNT:
                        switch (title)
                        {
                            case EventCountTitle.MY_WORKQUEUE_CATEGORY:
                            case EventCountTitle.All_WORKQUEUE:
                            case EventCountTitle.USER_WORKQUEUE:
                                return outDisplayData.Where(a => a.Priority == (int)EventPriorityEnum.Critical).ToList();
                            case EventCountTitle.MY_PENDED:
                                break;
                        }
                        break;
                    case EventCountType.OLDEST_COUNT:
                        switch (title)
                        {
                            case EventCountTitle.MY_WORKQUEUE_CATEGORY:
                            case EventCountTitle.All_WORKQUEUE:
                            case EventCountTitle.USER_WORKQUEUE:
                                return outDisplayData;
                            case EventCountTitle.MY_PENDED:
                                break;
                        }
                        break;
                    case EventCountType.PENDED_COUNT:
                        switch (title)
                        {
                            case EventCountTitle.MY_WORKQUEUE_CATEGORY:
                            case EventCountTitle.USER_WORKQUEUE:
                                return outDisplayData;
                            case EventCountTitle.MY_PENDED:
                                break;
                        }
                        break;
                    case EventCountType.TOTAL_COUNT:
                        switch (title)
                        {
                            case EventCountTitle.MY_WORKQUEUE_CATEGORY:
                            case EventCountTitle.All_WORKQUEUE:
                            case EventCountTitle.USER_WORKQUEUE:
                                return outDisplayData.ToList();
                            case EventCountTitle.MY_PENDED:
                                break;
                        }
                        break;
                }
            }


            return new List<DisplayData>();
        }

        public EventPublishResponse GetEventPublishedDetails(int goldenId)
        {
            EventPublishResponse publishResponse = new EventPublishResponse();
            try
            {
                var outboundMessagesSwift = (
                      from oms in this.context.OutboundMsts
                      join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                      join osms in this.context.OutboundSwiftRefMsts on oms.DestinationRefId equals osms.OutboundSwiftRefId
                      where (oms.GoldenRecordId == goldenId) &&
                        (oms.IsActive == 1) &&
                        (ams.IsActive == 1) &&
                        (osms.IsActive == 1) &&
                        (oms.Destination == "Swift")
                      select new EventPublishedDetail
                      {
                          BIC = ams.Bic,
                          LegalEntityName = ams.LegalEntityName,
                          //CIBCEntity = ams.CibcEntity,
                          outboundId = oms.OutboundId,
                          DestinationType = oms.Destination,
                          Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                          EventRefId = Convert.ToString(oms.GoldenRecordId),
                          SwiftMessage = "",
                          MessageType = osms.MsgType,
                          ParentCompanyName = ams.ParentCompanyName,
                          SEMERef = osms.SemeRef,
                          EntryDateTimeUtc = oms.EntryDtTimeUtc,
                          IsAutoStp = osms.AutoStp == 1,
                          EventType = "",
                          EmailMsg = "",
                          LegalEntityCdrId = oms.LegalEntityCdrId,
                          IsIgnore = oms.IsIgnore,
                          LinkageEventRef = oms.LinkageEventRef,
                          SendAction = oms.SendAction
                      }).Distinct().ToList();

                //outboundMessagesSwift = outboundMessagesSwift.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();

                var outboundMessagesEmail = (
                      from oms in this.context.OutboundMsts
                      join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                      join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                      where (oms.GoldenRecordId == goldenId) &&
                      (oms.IsActive == 1) &&
                      (ams.IsActive == 1) &&
                      (osms.IsActive == 1) &&
                      (oms.Destination == "Email")
                      select new EventPublishedDetail
                      {
                          BIC = ams.Bic,
                          LegalEntityName = ams.LegalEntityName,
                          //CIBCEntity = ams.CibcEntity,
                          outboundId = oms.OutboundId,
                          DestinationType = oms.Destination,
                          Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                          EventRefId = Convert.ToString(oms.GoldenRecordId),
                          SwiftMessage = "",
                          MessageType = osms.MsgType,
                          ParentCompanyName = ams.ParentCompanyName,
                          SEMERef = osms.SemeRef,
                          EntryDateTimeUtc = oms.EntryDtTimeUtc,
                          IsAutoStp = osms.AutoStp == 1,
                          EventType = "",
                          EmailMsg = "",
                          LegalEntityCdrId = oms.LegalEntityCdrId,
                          IsIgnore = oms.IsIgnore,
                          LinkageEventRef = oms.LinkageEventRef,
                          SendAction = oms.SendAction
                      }).Distinct().ToList();

                //outboundMessagesEmail = outboundMessagesEmail.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();

                // Under CR#112, a new email flow at the group level has been introduced.
                // GetEventPublishedDetails for each golden ID will now include records where
                // emails have been sent at the group level as well.
                var outboundMessagesEmailByGroup = (
                        from oms in this.context.OutboundMsts
                        join ams in this.context.TradingAccountGroups on oms.GroupId equals ams.Group_Id
                        join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                        where (oms.GoldenRecordId == goldenId) &&
                        (oms.IsActive == 1) &&
                        (ams.Is_Active == 1) &&
                        (osms.IsActive == 1) &&
                        (oms.IsAccountGroup == 1) &&
                        (oms.Destination == "Email")
                        select new EventPublishedDetail
                        {
                            BIC = "",
                            LegalEntityName = "",
                            //CIBCEntity = ams.CibcEntity,
                            outboundId = oms.OutboundId,
                            DestinationType = oms.Destination,
                            Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                            EventRefId = Convert.ToString(oms.GoldenRecordId),
                            SwiftMessage = "",
                            MessageType = osms.MsgType,
                            ParentCompanyName = "",
                            SEMERef = osms.SemeRef,
                            EntryDateTimeUtc = oms.EntryDtTimeUtc,
                            IsAutoStp = osms.AutoStp == 1,
                            EventType = "",
                            EmailMsg = "",
                            LegalEntityCdrId = "",
                            IsIgnore = oms.IsIgnore,
                            LinkageEventRef = oms.LinkageEventRef,
                            SendAction = oms.SendAction,
                            GroupId = oms.GroupId,
                            Group_Name = ams.Group_Name
                        }).Distinct().ToList();

                publishResponse.PublishDetails = outboundMessagesSwift.Union(outboundMessagesEmail).Union(outboundMessagesEmailByGroup).OrderByDescending(x => x.EntryDateTimeUtc).ToList();
                publishResponse.IsSuccess = true;
                publishResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                publishResponse.MessageId = (int)ResponseCodeMessage.Successful;

            }
            catch (Exception ex)
            {
                publishResponse.IsSuccess = false;
                publishResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                publishResponse.MessageId = (int)ResponseCodeMessage.InternalServerError;
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return publishResponse;
        }

        public EventPublishResponse GetEventPublishedMsgDetails(long src_outbound_id, string msgType )
        {
            EventPublishResponse publishResponse = new EventPublishResponse();
            try
            {
                
                    List<EventPublishedDetail> temp = new List<EventPublishedDetail>();
                    if (msgType == "Swift")
                    {

                        var outboundMessagesSwift = (
                              from oms in this.context.OutboundMsts
                              join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                              join osms in this.context.OutboundSwiftRefMsts on oms.DestinationRefId equals osms.OutboundSwiftRefId
                              where (oms.OutboundId == src_outbound_id) &&
                                (oms.IsActive == 1) &&
                                (ams.IsActive == 1) &&
                                (osms.IsActive == 1) &&
                                (oms.Destination == "Swift")
                              select new EventPublishedDetail
                              {
                                  BIC = ams.Bic,
                                  LegalEntityName = ams.LegalEntityName,
                                  //CIBCEntity = ams.CibcEntity,
                                  outboundId = oms.OutboundId,
                                  DestinationType = oms.Destination,
                                  Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                                  EventRefId = Convert.ToString(oms.GoldenRecordId),
                                  SwiftMessage = osms.SwiftMsg,
                                  MessageType = osms.MsgType,
                                  ParentCompanyName = ams.ParentCompanyName,
                                  SEMERef = osms.SemeRef,
                                  EntryDateTimeUtc = oms.EntryDtTimeUtc,
                                  IsAutoStp = osms.AutoStp == 1,
                                  EventType = "",
                                  EmailMsg = "",
                                  LegalEntityCdrId = oms.LegalEntityCdrId,
                                  IsIgnore = oms.IsIgnore,
                                  LinkageEventRef = oms.LinkageEventRef,
                                  SendAction = oms.SendAction
                              }).Distinct().ToList();

                           //outboundMessagesSwift = outboundMessagesSwift.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();
                           temp = outboundMessagesSwift;
                    }
                    else
                    {

                        var outboundMessagesEmail = (
                              from oms in this.context.OutboundMsts
                              join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                              join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                              where (oms.OutboundId == src_outbound_id) &&
                              (oms.IsActive == 1) &&
                              (ams.IsActive == 1) &&
                              (osms.IsActive == 1) &&
                              (oms.Destination == "Email")
                              select new EventPublishedDetail
                              {
                                  BIC = ams.Bic,
                                  LegalEntityName = ams.LegalEntityName,
                                  //CIBCEntity = ams.CibcEntity,
                                  outboundId = oms.OutboundId,
                                  DestinationType = oms.Destination,
                                  Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                                  EventRefId = Convert.ToString(oms.GoldenRecordId),
                                  SwiftMessage = osms.EmailBody,
                                  MessageType = osms.MsgType,
                                  ParentCompanyName = ams.ParentCompanyName,
                                  SEMERef = osms.SemeRef,
                                  EntryDateTimeUtc = oms.EntryDtTimeUtc,
                                  IsAutoStp = osms.AutoStp == 1,
                                  EventType = "",
                                  EmailMsg = osms.EmailMsg,
                                  LegalEntityCdrId = oms.LegalEntityCdrId,
                                  IsIgnore = oms.IsIgnore,
                                  LinkageEventRef = oms.LinkageEventRef,
                                  SendAction = oms.SendAction
                              }).Distinct().ToList();
                            temp = outboundMessagesEmail;

                    if (temp.IsNullOrEmpty())
                    {
                        var outboundMessagesEmailByGroup = (
                            from oms in this.context.OutboundMsts
                            join ams in this.context.TradingAccountGroups on oms.GroupId equals ams.Group_Id
                            join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                            where (oms.OutboundId == src_outbound_id) &&
                            (oms.IsActive == 1) &&
                            (ams.Is_Active == 1) &&
                            (osms.IsActive == 1) &&
                            (oms.IsAccountGroup == 1) &&
                            (oms.Destination == "Email")
                            select new EventPublishedDetail
                            {
                                BIC = "",
                                LegalEntityName = "",
                                //CIBCEntity = ams.CibcEntity,
                                outboundId = oms.OutboundId,
                                DestinationType = oms.Destination,
                                Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                                EventRefId = Convert.ToString(oms.GoldenRecordId),
                                SwiftMessage = osms.EmailBody,
                                MessageType = osms.MsgType,
                                ParentCompanyName = "",
                                SEMERef = osms.SemeRef,
                                EntryDateTimeUtc = oms.EntryDtTimeUtc,
                                IsAutoStp = osms.AutoStp == 1,
                                EventType = "",
                                EmailMsg = osms.EmailMsg,
                                LegalEntityCdrId = "",
                                IsIgnore = oms.IsIgnore,
                                LinkageEventRef = oms.LinkageEventRef,
                                SendAction = oms.SendAction,
                                GroupId = oms.GroupId,
                                Group_Name = ams.Group_Name
                            }).Distinct().ToList();
                        temp = outboundMessagesEmailByGroup;
                    }
                 }
                publishResponse.PublishDetails = temp.Take(1).ToList();
                publishResponse.IsSuccess = true;
                publishResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                publishResponse.MessageId = (int)ResponseCodeMessage.Successful;
                
            }
            catch (Exception ex)
            {
                publishResponse.IsSuccess = false;
                publishResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                publishResponse.MessageId = (int)ResponseCodeMessage.InternalServerError;
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return publishResponse;
        }

        public EventPublishResponse GetAllEventPublishedMsgDetails(int goldenId, DateTime fromDate, DateTime toDate, int isHistoricalPending, Boolean fromEvent)
        {
            EventPublishResponse publishResponse = new EventPublishResponse();
            try
            {
                if(fromEvent)
                {
                    var outboundMessagesSwift = (
                      from oms in this.context.OutboundMsts
                      join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                      join osms in this.context.OutboundSwiftRefMsts on oms.DestinationRefId equals osms.OutboundSwiftRefId
                      where (oms.GoldenRecordId == goldenId) &&
                        (oms.IsActive == 1) &&
                        (ams.IsActive == 1) &&
                        (osms.IsActive == 1) &&
                        (oms.Destination == "Swift")
                      select new EventPublishedDetail
                      {
                          BIC = ams.Bic,
                          LegalEntityName = ams.LegalEntityName,
                          //CIBCEntity = ams.CibcEntity,
                          outboundId = oms.OutboundId,
                          DestinationType = oms.Destination,
                          Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                          EventRefId = Convert.ToString(oms.GoldenRecordId),
                          SwiftMessage = osms.SwiftMsg,
                          MessageType = osms.MsgType,
                          ParentCompanyName = ams.ParentCompanyName,
                          SEMERef = osms.SemeRef,
                          EntryDateTimeUtc = oms.EntryDtTimeUtc,
                          IsAutoStp = osms.AutoStp == 1,
                          EventType = "",
                          EmailMsg = "",
                          LegalEntityCdrId = oms.LegalEntityCdrId,
                          IsIgnore = oms.IsIgnore,
                          LinkageEventRef = oms.LinkageEventRef,
                          SendAction = oms.SendAction
                      }).Distinct().ToList();

                    //outboundMessagesSwift = outboundMessagesSwift.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();

                    var outboundMessagesEmail = (
                          from oms in this.context.OutboundMsts
                          join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                          join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                          where (oms.GoldenRecordId == goldenId) &&
                          (oms.IsActive == 1) &&
                          (ams.IsActive == 1) &&
                          (osms.IsActive == 1) &&
                          (oms.Destination == "Email")
                          select new EventPublishedDetail
                          {
                              BIC = ams.Bic,
                              LegalEntityName = ams.LegalEntityName,
                              //CIBCEntity = ams.CibcEntity,
                              outboundId = oms.OutboundId,
                              DestinationType = oms.Destination,
                              Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                              EventRefId = Convert.ToString(oms.GoldenRecordId),
                              SwiftMessage = osms.EmailBody,
                              MessageType = osms.MsgType,
                              ParentCompanyName = ams.ParentCompanyName,
                              SEMERef = osms.SemeRef,
                              EntryDateTimeUtc = oms.EntryDtTimeUtc,
                              IsAutoStp = osms.AutoStp == 1,
                              EventType = "",
                              EmailMsg = osms.EmailMsg,
                              LegalEntityCdrId = oms.LegalEntityCdrId,
                              IsIgnore = oms.IsIgnore,
                              LinkageEventRef = oms.LinkageEventRef,
                              SendAction = oms.SendAction
                          }).Distinct().ToList();

                    // Under CR#112, a new email flow at the group level has been introduced.
                    // GetAllEventPublishedMsgDetails for each golden ID will now include records where
                    // emails have been sent at the group level as well.
                    var outboundMessagesEmailByGroup = (
                        from oms in this.context.OutboundMsts
                        join ams in this.context.TradingAccountGroups on oms.GroupId equals ams.Group_Id
                        join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                        where (oms.GoldenRecordId == goldenId) &&
                        (oms.IsActive == 1) &&
                        (ams.Is_Active == 1) &&
                        (osms.IsActive == 1) &&
                        (oms.IsAccountGroup == 1) &&
                        (oms.Destination == "Email")
                        select new EventPublishedDetail
                        {
                            BIC = "",
                            LegalEntityName = "",
                            //CIBCEntity = ams.CibcEntity,
                            outboundId = oms.OutboundId,
                            DestinationType = oms.Destination,
                            Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                            EventRefId = Convert.ToString(oms.GoldenRecordId),
                            SwiftMessage = osms.EmailBody,
                            MessageType = osms.MsgType,
                            ParentCompanyName = "",
                            SEMERef = osms.SemeRef,
                            EntryDateTimeUtc = oms.EntryDtTimeUtc,
                            IsAutoStp = osms.AutoStp == 1,
                            EventType = "",
                            EmailMsg = osms.EmailMsg,
                            LegalEntityCdrId = "",
                            IsIgnore = oms.IsIgnore,
                            LinkageEventRef = oms.LinkageEventRef,
                            SendAction = oms.SendAction,
                            GroupId = oms.GroupId,
                            Group_Name = ams.Group_Name
                        }).Distinct().ToList();

                    //outboundMessagesEmail = outboundMessagesEmail.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();

                    publishResponse.PublishDetails = outboundMessagesSwift.Union(outboundMessagesEmail).Union(outboundMessagesEmailByGroup).OrderByDescending(x => x.EntryDateTimeUtc).ToList();
                    publishResponse.IsSuccess = true;
                    publishResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                    publishResponse.MessageId = (int)ResponseCodeMessage.Successful;
                }
                else
                {
                    List<EventPublishedDetail> outboundMessagesSwift = null;
                    List<EventPublishedDetail> outboundMessagesEmail = null;
                    List<EventPublishedDetail> outboundMessagesEmailByGroup = null;

                    if (isHistoricalPending == 0)
                    {
                        outboundMessagesSwift = (
                              from oms in this.context.OutboundMsts
                              join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                              join osms in this.context.OutboundSwiftRefMsts on oms.DestinationRefId equals osms.OutboundSwiftRefId
                              join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                              where ((oms.EntryDtTimeUtc >= fromDate) &&
                              (oms.EntryDtTimeUtc <= toDate)) &&
                              (oms.IsActive == 1) &&
                              (ams.IsActive == 1) &&
                              (osms.IsActive == 1) &&
                              oms.Destination == "Swift"
                              select new EventPublishedDetail
                              {
                                  BIC = ams.Bic,
                                  LegalEntityName = ams.LegalEntityName,
                                  //CIBCEntity = ams.CibcEntity,
                                  outboundId = oms.OutboundId,
                                  DestinationType = oms.Destination,
                                  Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                                  EventRefId = Convert.ToString(oms.GoldenRecordId),
                                  SwiftMessage = osms.SwiftMsg,
                                  MessageType = osms.MsgType,
                                  ParentCompanyName = ams.ParentCompanyName,
                                  SEMERef = osms.SemeRef,
                                  EntryDateTimeUtc = oms.EntryDtTimeUtc,
                                  IsAutoStp = osms.AutoStp == 1,
                                  EventType = grm.EventName,
                                  EmailMsg = "",
                                  LegalEntityCdrId = oms.LegalEntityCdrId,
                                  IsIgnore = oms.IsIgnore,
                                  LinkageEventRef = oms.LinkageEventRef,
                                  SendAction = oms.SendAction
                              }).Distinct().ToList();

                        //outboundMessagesSwift = outboundMessagesSwift.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();

                        outboundMessagesEmail = (
                              from oms in this.context.OutboundMsts
                              join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                              join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                              join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                              where ((oms.EntryDtTimeUtc >= fromDate) &&
                              (oms.EntryDtTimeUtc <= toDate)) &&
                              (oms.IsActive == 1) &&
                              (ams.IsActive == 1) &&
                              (osms.IsActive == 1) &&
                              oms.Destination == "Email"
                              select new EventPublishedDetail
                              {
                                  BIC = ams.Bic,
                                  LegalEntityName = ams.LegalEntityName,
                                  //CIBCEntity = ams.CibcEntity,
                                  outboundId = oms.OutboundId,
                                  DestinationType = oms.Destination,
                                  Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                                  EventRefId = Convert.ToString(oms.GoldenRecordId),
                                  SwiftMessage = osms.EmailBody,
                                  MessageType = osms.MsgType,
                                  ParentCompanyName = ams.ParentCompanyName,
                                  SEMERef = osms.SemeRef,
                                  EntryDateTimeUtc = oms.EntryDtTimeUtc,
                                  IsAutoStp = osms.AutoStp == 1,
                                  EventType = grm.EventName,
                                  EmailMsg = osms.EmailMsg,
                                  LegalEntityCdrId = oms.LegalEntityCdrId,
                                  IsIgnore = oms.IsIgnore,
                                  LinkageEventRef = oms.LinkageEventRef,
                                  SendAction = oms.SendAction
                              }).Distinct().ToList();

                        //outboundMessagesEmail = outboundMessagesEmail.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();
                        
                        // Under CR#112, a new email flow at the group level has been introduced.
                        // GetAllEventPublishedMsgDetails for each golden ID will now include records where
                        // emails have been sent at the group level as well.
                        outboundMessagesEmailByGroup = (
                            from oms in this.context.OutboundMsts
                            join ams in this.context.TradingAccountGroups on oms.GroupId equals ams.Group_Id
                            join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                            join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                            where ((oms.EntryDtTimeUtc >= fromDate) &&
                            (oms.EntryDtTimeUtc <= toDate)) &&
                            (oms.IsActive == 1) &&
                            (oms.IsAccountGroup == 1)&&
                            (ams.Is_Active == 1) &&
                            (osms.IsActive == 1) &&
                            oms.Destination == "Email"
                            select new EventPublishedDetail
                            {
                                BIC = "",
                                LegalEntityName = "",
                                //CIBCEntity = ams.CibcEntity,
                                outboundId = oms.OutboundId,
                                DestinationType = oms.Destination,
                                Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                                EventRefId = Convert.ToString(oms.GoldenRecordId),
                                SwiftMessage = osms.EmailBody,
                                MessageType = osms.MsgType,
                                ParentCompanyName = "",
                                SEMERef = osms.SemeRef,
                                EntryDateTimeUtc = oms.EntryDtTimeUtc,
                                IsAutoStp = osms.AutoStp == 1,
                                EventType = grm.EventName,
                                EmailMsg = osms.EmailMsg,
                                LegalEntityCdrId = "",
                                IsIgnore = oms.IsIgnore,
                                LinkageEventRef = oms.LinkageEventRef,
                                SendAction = oms.SendAction,
                                Group_Name = ams.Group_Name,
                                GroupId = ams.Group_Id
                            }).Distinct().ToList();
                    }
                    else
                    {
                        outboundMessagesSwift = (
                              from oms in this.context.OutboundMsts
                              join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                              join osms in this.context.OutboundSwiftRefMsts on oms.DestinationRefId equals osms.OutboundSwiftRefId
                              join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                              where (oms.EntryDtTimeUtc < fromDate) &&
                              (oms.IsActive == 1) &&
                              (ams.IsActive == 1) &&
                              (osms.IsActive == 1) &&
                              oms.Destination == "Swift" &&
                              (oms.OutboundStatus.ToLower() == "swiftnack" || oms.OutboundStatus.ToLower() == "amhnack" || oms.OutboundStatus.ToLower() == "nack")
                              select new EventPublishedDetail
                              {
                                  BIC = ams.Bic,
                                  LegalEntityName = ams.LegalEntityName,
                                  //CIBCEntity = ams.CibcEntity,
                                  outboundId = oms.OutboundId,
                                  DestinationType = oms.Destination,
                                  Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                                  EventRefId = Convert.ToString(oms.GoldenRecordId),
                                  SwiftMessage = osms.SwiftMsg,
                                  MessageType = osms.MsgType,
                                  ParentCompanyName = ams.ParentCompanyName,
                                  SEMERef = osms.SemeRef,
                                  EntryDateTimeUtc = oms.EntryDtTimeUtc,
                                  IsAutoStp = osms.AutoStp == 1,
                                  EventType = grm.EventName,
                                  EmailMsg = "",
                                  LegalEntityCdrId = oms.LegalEntityCdrId,
                                  IsIgnore = oms.IsIgnore,
                                  LinkageEventRef = oms.LinkageEventRef,
                                  SendAction = oms.SendAction
                              }).Distinct().ToList();

                        //outboundMessagesSwift = outboundMessagesSwift.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();

                        outboundMessagesEmail = (
                              from oms in this.context.OutboundMsts
                              join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                              join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                              join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                              where (oms.EntryDtTimeUtc < fromDate) &&
                              (oms.IsActive == 1) &&
                              (ams.IsActive == 1) &&
                              (osms.IsActive == 1) &&
                              oms.Destination == "Email" &&
                              (oms.OutboundStatus.ToLower() == "swiftnack" || oms.OutboundStatus.ToLower() == "amhnack" || oms.OutboundStatus.ToLower() == "nack")
                              select new EventPublishedDetail
                              {
                                  BIC = ams.Bic,
                                  LegalEntityName = ams.LegalEntityName,
                                  //CIBCEntity = ams.CibcEntity,
                                  outboundId = oms.OutboundId,
                                  DestinationType = oms.Destination,
                                  Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                                  EventRefId = Convert.ToString(oms.GoldenRecordId),
                                  SwiftMessage = osms.EmailBody,
                                  MessageType = osms.MsgType,
                                  ParentCompanyName = ams.ParentCompanyName,
                                  SEMERef = osms.SemeRef,
                                  EntryDateTimeUtc = oms.EntryDtTimeUtc,
                                  IsAutoStp = osms.AutoStp == 1,
                                  EventType = grm.EventName,
                                  EmailMsg = osms.EmailMsg,
                                  LegalEntityCdrId = oms.LegalEntityCdrId,
                                  IsIgnore = oms.IsIgnore,
                                  LinkageEventRef = oms.LinkageEventRef,
                                  SendAction = oms.SendAction
                              }).Distinct().ToList();

                        // Under CR#112, a new email flow at the group level has been introduced.
                        // GetAllEventPublishedMsgDetails for each golden ID will now include records where
                        // emails have been sent at the group level as well.
                        outboundMessagesEmailByGroup = (
                                from oms in this.context.OutboundMsts
                                join ams in this.context.TradingAccountGroups on oms.GroupId equals ams.Group_Id
                                join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                                join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                                where ((oms.EntryDtTimeUtc >= fromDate) &&
                                (oms.EntryDtTimeUtc <= toDate)) &&
                                (oms.IsActive == 1) &&
                                (oms.IsAccountGroup == 1) &&
                                (ams.Is_Active == 1) &&
                                (osms.IsActive == 1) &&
                                oms.Destination == "Email" &&
                                (oms.OutboundStatus.ToLower() == "swiftnack" || oms.OutboundStatus.ToLower() == "amhnack" || oms.OutboundStatus.ToLower() == "nack")
                                select new EventPublishedDetail
                                {
                                    BIC = "",
                                    LegalEntityName = "",
                                    //CIBCEntity = ams.CibcEntity,
                                    outboundId = oms.OutboundId,
                                    DestinationType = oms.Destination,
                                    Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                                    EventRefId = Convert.ToString(oms.GoldenRecordId),
                                    SwiftMessage = osms.EmailBody,
                                    MessageType = osms.MsgType,
                                    ParentCompanyName = "",
                                    SEMERef = osms.SemeRef,
                                    EntryDateTimeUtc = oms.EntryDtTimeUtc,
                                    IsAutoStp = osms.AutoStp == 1,
                                    EventType = grm.EventName,
                                    EmailMsg = osms.EmailMsg,
                                    LegalEntityCdrId = "",
                                    IsIgnore = oms.IsIgnore,
                                    LinkageEventRef = oms.LinkageEventRef,
                                    SendAction = oms.SendAction,
                                    Group_Name = ams.Group_Name,
                                    GroupId = ams.Group_Id
                                }).Distinct().ToList();
                    }

                    publishResponse.PublishDetails = outboundMessagesSwift.Union(outboundMessagesEmail).Union(outboundMessagesEmailByGroup).ToList();
                    publishResponse.IsSuccess = true;
                    publishResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                    publishResponse.MessageId = (int)ResponseCodeMessage.Successful;
                }

            }
            catch (Exception ex)
            {
                publishResponse.IsSuccess = false;
                publishResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                publishResponse.MessageId = (int)ResponseCodeMessage.InternalServerError;
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return publishResponse;
        
    }
        public List<CaEventMst> GetEvents(int eventId)
        {
            List<CaEventMst> events = new List<CaEventMst>();

            try
            {
                if (eventId == 0)
                {
                    events = this.context.CaEventMsts.Where(x => x.IsActive == 1).ToList();
                }
                else
                {
                    events = this.context.CaEventMsts.Where(c => c.CaEventMstId == eventId).ToList();
                }
            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }

            return events;
        }

        public List<CaEventTypeMst> GetEventTypes(int eventTypeId)
        {
            List<CaEventTypeMst> eventTypes = new List<CaEventTypeMst>();

            try
            {
                if (eventTypeId == 0)
                {
                    eventTypes = this.context.CaEventTypeMsts.Where(x => x.IsActive == 1).ToList();
                }
                else
                {
                    eventTypes = this.context.CaEventTypeMsts.Where(c => c.CaEventTypeId == eventTypeId).ToList();
                }
            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }

            return eventTypes;
        }
        public List<CaEventEventTypeMapping> GetEventAndEventTypeMapping()
        {
            List<CaEventEventTypeMapping> eventAndEventTypeMapping = new List<CaEventEventTypeMapping>();

            try
            {
                eventAndEventTypeMapping = this.context.CaEventEventTypeMappings.ToList();
            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }

            return eventAndEventTypeMapping;
        }
        public EventOptionPositionsWithType GetEventOptionPositions(int goldenId)
        {
            EventOptionPositionsWithType eventOptionPositionsModel = new EventOptionPositionsWithType();

            try
            {
                var positionType = (from grm in this.context.GoldenRecordMsts
                                    join gpd in this.context.CaEventGpdConfigs on grm.GpdDateType equals gpd.GpdDateType
                                    where grm.GoldenRecordId == goldenId
                                    select new
                                    {
                                        GoldenRecordId = grm.GoldenRecordId,
                                        PositionType = gpd.PositionType
                                    }).FirstOrDefault();


                var eventAccounts = (from o in this.context.CaEventElectionOptionsDtls
                                     where (o.GoldenRecordId == goldenId) && o.IsActive == 1
                                     select new
                                     {
                                         TradingAccount = o.TradingAccount,
                                         //Mt564SemeRef = ""
                                     }).ToList();

                // Under CR#112, a new email flow at the group level has been introduced.
                // To ensure the existing email flow in each module remains unaffected,
                // a check for (g.IsAccountGroup == 0) has been added.
                var mt564Accounts = (from o in this.context.OutBoundAccountMappings
                                     join g in this.context.OutboundMsts on o.OutboundId equals g.OutboundId
                                     where (g.GoldenRecordId == goldenId) && o.IsActive == 1 && o.TradingAccountNumber != null 
                                     && g.IsAccountGroup == 0
                                     select new
                                     {
                                         TradingAccount = o.TradingAccountNumber,
                                         //Mt564SemeRef = g.GeneratedEventRef
                                     }).ToList();

                var details = (from o in this.context.CaEventElectionOptionsDtls
                               join a in this.context.CaEventElectionMappings on o.CaEventElectionMappingId equals a.CaEventElectionMappingId
                               where o.IsActive == 1 && o.GoldenRecordId == goldenId
                               select new EventOptionPositionDetailModel
                               {
                                   CaEventElectionOptionsDtlId = o.CaEventElectionOptionsDtlId,
                                   CaEventElectionMappingId = o.CaEventElectionMappingId,
                                   TradingAccount = o.TradingAccount,
                                   OptionNumber = o.OptionNumber,
                                   OptionStatus = o.OptionStatus,
                                   OptionType = o.OptionType,
                                   Currency = o.Currency,
                                   CurrencyId = o.CurrencyId,
                                   Price = o.Price,
                                   Qty = o.Qty,
                                   Rate = o.Rate,
                                   Default = a.IsDefault,
                                   ExternalComment = o.ExternalComment
                               }).ToList();

                if (this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == goldenId && x.IsActive == 1 && x.IsPositionCaptured == true).Any())
                {
                    var accounts = (from o in this.context.CaEventElectionPositions
                                    where (o.GoldenRecordId == goldenId) && o.IsActive == 1
                                    select new
                                    {
                                        TradingAccount = o.TradingAccountNumber + "-" + o.AccountType,
                                        //Mt564SemeRef = string.Empty

                                    }).ToList();

                    var totalAccounts = accounts.Union(eventAccounts).Union(mt564Accounts).ToList();
                    if (totalAccounts != null)
                    {
                        totalAccounts.ForEach(i =>
                        {
                            string tradingAccnt = i.TradingAccount.ToString();
                            // Under CR#112, a new email flow at the group level has been introduced.
                            // To ensure the existing email flow in each module remains unaffected,
                            // a check for (g.IsAccountGroup == 0) has been added.
                            var query = (from xa in this.context.OutBoundAccountMappings
                                         join g in this.context.OutboundMsts on xa.OutboundId equals g.OutboundId
                                         //join h in this.context.OutboundSwiftRefMsts on g.DestinationRefId equals h.OutboundSwiftRefId
                                         where (g.GoldenRecordId == goldenId) && g.IsAccountGroup == 0 && xa.IsActive == 1 && xa.TradingAccountNumber != null && xa.TradingAccountNumber == tradingAccnt
                                         select new
                                         {
                                             FinalTradingAccount = tradingAccnt,
                                             Mt564SemeRef = g.GeneratedEventRef,
                                             OutboundId = g.OutboundId,
                                             Destination = g.Destination
                                         });

                            var materializedQueryForFinal = query.ToList();

                            var finalAccountsTemp = materializedQueryForFinal.GroupBy(x => x.FinalTradingAccount);

                            Dictionary<string, string> tempObj = new Dictionary<string, string>();
                            finalAccountsTemp.ForEach(x =>
                            {
                                if (x.Any(x => x.Destination == "Email") && x.Any(x => x.Destination == "Swift"))
                                {
                                    tempObj.Add(x.FirstOrDefault().FinalTradingAccount, "isSwift");
                                }
                                else if (x.Any(x => x.Destination == "Swift"))
                                {
                                    tempObj.Add(x.FirstOrDefault().FinalTradingAccount, "isSwift");
                                }
                                else
                                {
                                    tempObj.Add(x.FirstOrDefault().FinalTradingAccount, "isEmail");
                                }
                            });


                            List<FinalAccountsModel> lstObj = new List<FinalAccountsModel>();

                            tempObj.ForEach(tempDict =>
                            {
                                if (tempDict.Value == "isEmail")
                                {
                                    if (tradingAccnt == tempDict.Key)
                                    {
                                        // Under CR#112, a new email flow at the group level has been introduced.
                                        // To ensure the existing email flow in each module remains unaffected,
                                        // a check for (g.IsAccountGroup == 0) has been added.
                                        var query = from x in this.context.OutBoundAccountMappings
                                                    join g in this.context.OutboundMsts on x.OutboundId equals g.OutboundId
                                                    join h in this.context.OutboundEmailRefMsts on g.DestinationRefId equals h.OutboundEmailRefId
                                                    where (g.GoldenRecordId == goldenId) &&
                                                          g.Destination == "Email" &&
                                                          h.MsgType == "564" &&
                                                          x.IsActive == 1 &&
                                                          x.TradingAccountNumber != null &&
                                                          x.TradingAccountNumber == tempDict.Key && 
                                                          g.IsAccountGroup == 0
                                                    select new FinalAccountsModel
                                                    {
                                                        FinalTradingAccount = tradingAccnt,
                                                        Mt564SemeRef = g.GeneratedEventRef,
                                                        OutboundId = g.OutboundId,
                                                        Destination = g.Destination
                                                    };
                                        // Bring the data into memory before applying GroupBy and OrderByDescending
                                        var materializedQuery = query.ToList();
                                        var groupedQuery = materializedQuery.GroupBy(x => x.FinalTradingAccount);
                                        var orderedQuery = groupedQuery.Select(g => g.OrderByDescending(e => e.OutboundId).First());
                                        lstObj.Add(orderedQuery.FirstOrDefault());
                                    }
                                }
                                else
                                {
                                    if (tradingAccnt == tempDict.Key)
                                    {
                                        // Under CR#112, a new email flow at the group level has been introduced.
                                        // To ensure the existing email flow in each module remains unaffected,
                                        // a check for (g.IsAccountGroup == 0) has been added.
                                        var query = from x in this.context.OutBoundAccountMappings
                                                    join g in this.context.OutboundMsts on x.OutboundId equals g.OutboundId
                                                    join h in this.context.OutboundSwiftRefMsts on g.DestinationRefId equals h.OutboundSwiftRefId
                                                    where (g.GoldenRecordId == goldenId) &&
                                                          g.Destination == "Swift" &&
                                                          h.MsgType == "564" &&
                                                          x.IsActive == 1 &&
                                                          x.TradingAccountNumber != null &&
                                                          x.TradingAccountNumber == tempDict.Key &&
                                                          g.IsAccountGroup == 0
                                                    select new FinalAccountsModel
                                                    {
                                                        FinalTradingAccount = tradingAccnt,
                                                        Mt564SemeRef = g.GeneratedEventRef,
                                                        OutboundId = g.OutboundId,
                                                        Destination = g.Destination
                                                    };
                                        // Bring the data into memory before applying GroupBy and OrderByDescending
                                        var materializedQuery = query.ToList();
                                        var groupedQuery = materializedQuery.GroupBy(x => x.FinalTradingAccount);
                                        var orderedQuery = groupedQuery.Select(g => g.OrderByDescending(e => e.OutboundId).First());
                                        lstObj.Add(orderedQuery.FirstOrDefault());
                                    }
                                }
                            });

                            LogUtility.Logger.Logger.Log("Position will calculated Using CaEventElectionPositions", LogType.Debug);
                            LogUtility.Logger.Logger.Log($"Final Account {JsonConvert.SerializeObject(lstObj)}", LogType.Debug);
                            var x = new List<CaapsWebServer.Models.Generic.FinalAccountsModel>();
                            if (lstObj != null && lstObj.Count > 0)
                            {
                                x = lstObj
                                .Where(fa => totalAccounts.Any(t => t.TradingAccount == fa.FinalTradingAccount))
                                .ToList();
                            }
                            var grGroup = this.context.GoldenRecordMsts.Where(g => g.GoldenRecordId == goldenId).ToList();
                            EventOptionPositionsWithType tempResult = new EventOptionPositionsWithType();
                            tempResult.EventOptionPositionsModel = (
                                                                                from o in x.DefaultIfEmpty()
                                                                                from gr in grGroup.DefaultIfEmpty()
                                                                                join a in this.context.CaEventElectionPositions on tradingAccnt equals a.TradingAccountNumber + "-" + a.AccountType into eventElectionPositionGroup
                                                                                from clientPositionDtl in eventElectionPositionGroup.Where(a => a.IsActive == 1 && gr.GoldenRecordId == a.GoldenRecordId).DefaultIfEmpty()
                                                                                join am in this.context.AccountMsts on tradingAccnt.Split('-')[0] equals am.TradingAccountNumber into actMstGroup
                                                                                from actMst in actMstGroup.Where(a => a.IsActive == 1).DefaultIfEmpty()
                                                                                select new EventOptionPositionsModel
                                                                                {
                                                                                    Mt564SemeRef = o?.Mt564SemeRef ?? String.Empty,
                                                                                    TradingAccountNumber = tradingAccnt,
                                                                                    CDR = actMst?.LegalEntityName ?? "",
                                                                                    Position = (clientPositionDtl != null) ? (positionType.PositionType == "TRAD" ? clientPositionDtl.TradeDatePosition : clientPositionDtl.SettleDatePosition) : 0,
                                                                                    TradePosition = clientPositionDtl?.TradeDatePosition ?? 0,
                                                                                    SettlePosition = clientPositionDtl?.SettleDatePosition ?? 0,
                                                                                    TotalElectedPosition = details.Where(c => c.TradingAccount == tradingAccnt && (c.OptionStatus == "INSTRUCTION_ACCEPTED" || c.OptionStatus == "INSTRUCTION_DEFAULT")).Sum(c => c.Qty),
                                                                                    TotalUnElectedPosition = (clientPositionDtl != null) ? ((positionType != null && positionType.PositionType == "TRAD") ? clientPositionDtl.TradeDatePosition : clientPositionDtl.SettleDatePosition) - details.Where(c => c.TradingAccount == tradingAccnt && (c.OptionStatus == "INSTRUCTION_ACCEPTED" || c.OptionStatus == "INSTRUCTION_DEFAULT")).Sum(c => c.Qty) : 0,
                                                                                    PendingPosition = details.Where(c => c.TradingAccount == tradingAccnt && c.OptionStatus == "PENDING_INSTRUCTION").Sum(c => c.Qty),
                                                                                    PendingCancellation = details.Where(c => c.TradingAccount == tradingAccnt && c.OptionStatus == "PENDING_CANCELLATION").Sum(c => c.Qty),
                                                                                    Accounttype = (clientPositionDtl != null) ? (String.IsNullOrEmpty(clientPositionDtl.AccountType) ? "" : this.enumHelper.GetEnumDescription((AccountTypeEnum)Convert.ToInt32(clientPositionDtl.AccountType))) : this.enumHelper.GetEnumDescription((AccountTypeEnum)int.Parse(tradingAccnt.Substring(tradingAccnt.LastIndexOf('-') + 1, tradingAccnt.Length - (tradingAccnt.LastIndexOf('-') + 1)))),
                                                                                    EventOptionPositionDetails = details.Where(c => c.TradingAccount == tradingAccnt).ToList(),
                                                                                    SwiftOrEmail = actMst != null ?
                                                                                     (actMst.SwiftMessageEnabled != null ?

                                                                                        (actMst.SwiftMessageEnabled.ToUpper() == "Y" ?
                                                                                            (actMst.EmailEnabled != null ?
                                                                                                (actMst.EmailEnabled.ToUpper() == "Y" ? "Swift,Email" : "Swift") :
                                                                                                "Swift"
                                                                                            ) :
                                                                                            (actMst.EmailEnabled != null ?
                                                                                                (actMst.EmailEnabled.ToUpper() == "Y" ? "Email" : "none") :
                                                                                                "none"
                                                                                            )
                                                                                        ) :
                                                                                        (actMst.EmailEnabled != null ?
                                                                                            (actMst.EmailEnabled.ToUpper() == "Y" ? "Email" : "none") :
                                                                                            "none"
                                                                                        )
                                                                                    ) : "",
                                                                                    PositionType = positionType?.PositionType,
                                                                                    CIBCEntity = actMst?.CibcEntity
                                                                                }).Where(x => !string.IsNullOrEmpty(x.CDR)).DistinctBy(a => a.TradingAccountNumber).ToList();
                            LogUtility.Logger.Logger.Log("OK1", LogType.Debug);
                            if (tempResult.EventOptionPositionsModel != null)
                            {
                                if (eventOptionPositionsModel.EventOptionPositionsModel == null)
                                {
                                    eventOptionPositionsModel.EventOptionPositionsModel = new List<EventOptionPositionsModel>();
                                }

                                eventOptionPositionsModel.EventOptionPositionsModel.AddRange(tempResult.EventOptionPositionsModel);
                            }
                        });
                    }
                    }
                else
                {
                    var accounts = (from o in this.context.ClientPositionDtls
                                    join g in this.context.GoldenRecordMsts on o.BloombergId equals g.BloombergId
                                    where (g.GoldenRecordId == goldenId) && o.IsActive == 1
                                    select new
                                    {
                                        TradingAccount = o.TradingAccountNumber + "-" + o.Accounttype,
                                    }).ToList();

                    var totalAccounts = accounts.Union(eventAccounts).Union(mt564Accounts).ToList();
                    if (totalAccounts != null)
                    {
                        totalAccounts.ForEach(i =>
                    {
                        string tradingAccnt = i.TradingAccount.ToString();
                        // Under CR#112, a new email flow at the group level has been introduced.
                        // To ensure the existing email flow in each module remains unaffected,
                        // a check for (g.IsAccountGroup == 0) has been added.
                        var query = (from xa in this.context.OutBoundAccountMappings
                                     join g in this.context.OutboundMsts on xa.OutboundId equals g.OutboundId
                                     //join h in this.context.OutboundSwiftRefMsts on g.DestinationRefId equals h.OutboundSwiftRefId
                                     where (g.GoldenRecordId == goldenId) && xa.IsActive == 1 && g.IsAccountGroup == 0 && xa.TradingAccountNumber != null && xa.TradingAccountNumber == tradingAccnt
                                     select new
                                     {
                                         FinalTradingAccount = tradingAccnt,
                                         Mt564SemeRef = g.GeneratedEventRef,
                                         OutboundId = g.OutboundId,
                                         Destination = g.Destination
                                     });

                        var materializedQueryForFinal = query.ToList();

                        var finalAccountsTemp = materializedQueryForFinal.GroupBy(x => x.FinalTradingAccount);

                        Dictionary<string, string> tempObj = new Dictionary<string, string>();
                        finalAccountsTemp.ForEach(x =>
                        {
                            if (x.Any(x => x.Destination == "Email") && x.Any(x => x.Destination == "Swift"))
                            {
                                tempObj.Add(x.FirstOrDefault().FinalTradingAccount, "isSwift");
                            }
                            else if (x.Any(x => x.Destination == "Swift"))
                            {
                                tempObj.Add(x.FirstOrDefault().FinalTradingAccount, "isSwift");
                            }
                            else
                            {
                                tempObj.Add(x.FirstOrDefault().FinalTradingAccount, "isEmail");
                            }
                        });


                        List<FinalAccountsModel> lstObj = new List<FinalAccountsModel>();

                        tempObj.ForEach(tempDict =>
                        {
                            if (tempDict.Value == "isEmail")
                            {
                                if (tradingAccnt == tempDict.Key)
                                {
                                    // Under CR#112, a new email flow at the group level has been introduced.
                                    // To ensure the existing email flow in each module remains unaffected,
                                    // a check for (g.IsAccountGroup == 0) has been added.
                                    var query = from x in this.context.OutBoundAccountMappings
                                                join g in this.context.OutboundMsts on x.OutboundId equals g.OutboundId
                                                join h in this.context.OutboundEmailRefMsts on g.DestinationRefId equals h.OutboundEmailRefId
                                                where (g.GoldenRecordId == goldenId) &&
                                                  g.Destination == "Email" &&
                                                  h.MsgType == "564" &&
                                                  x.IsActive == 1 &&
                                                  x.TradingAccountNumber != null &&
                                                  x.TradingAccountNumber == tempDict.Key && 
                                                  g.IsAccountGroup == 0
                                                select new FinalAccountsModel
                                                {
                                                    FinalTradingAccount = tradingAccnt,
                                                    Mt564SemeRef = g.GeneratedEventRef,
                                                    OutboundId = g.OutboundId,
                                                    Destination = g.Destination
                                                };
                                    // Bring the data into memory before applying GroupBy and OrderByDescending
                                    var materializedQuery = query.ToList();
                                    var groupedQuery = materializedQuery.GroupBy(x => x.FinalTradingAccount);
                                    var orderedQuery = groupedQuery.Select(g => g.OrderByDescending(e => e.OutboundId).First());
                                    lstObj.Add(orderedQuery.FirstOrDefault());
                                }
                            }
                            else
                            {
                                if (tradingAccnt == tempDict.Key)
                                {
                                    // Under CR#112, a new email flow at the group level has been introduced.
                                    // To ensure the existing email flow in each module remains unaffected,
                                    // a check for (g.IsAccountGroup == 0) has been added.
                                    var query = from x in this.context.OutBoundAccountMappings
                                                join g in this.context.OutboundMsts on x.OutboundId equals g.OutboundId
                                                join h in this.context.OutboundSwiftRefMsts on g.DestinationRefId equals h.OutboundSwiftRefId
                                                where (g.GoldenRecordId == goldenId) &&
                                                  g.Destination == "Swift" &&
                                                  h.MsgType == "564" &&
                                                  x.IsActive == 1 &&
                                                  x.TradingAccountNumber != null &&
                                                  x.TradingAccountNumber == tempDict.Key && 
                                                  g.IsAccountGroup == 0
                                                select new FinalAccountsModel
                                                {
                                                    FinalTradingAccount = tradingAccnt,
                                                    Mt564SemeRef = g.GeneratedEventRef,
                                                    OutboundId = g.OutboundId,
                                                    Destination = g.Destination
                                                };

                                    // Bring the data into memory before applying GroupBy and OrderByDescending
                                    var materializedQuery = query.ToList();
                                    var groupedQuery = materializedQuery.GroupBy(x => x.FinalTradingAccount);
                                    var orderedQuery = groupedQuery.Select(g => g.OrderByDescending(e => e.OutboundId).First());
                                    lstObj.Add(orderedQuery.FirstOrDefault());
                                }

                            }
                        });

                        LogUtility.Logger.Logger.Log("Position will calculated Using ClientPositionDtls", LogType.Debug);
                        LogUtility.Logger.Logger.Log($"Final Account {JsonConvert.SerializeObject(lstObj)}", LogType.Debug);
                        var x = new List<CaapsWebServer.Models.Generic.FinalAccountsModel>();
                        if (lstObj != null && lstObj.Count>0)
                        {
                            x = lstObj
                            .Where(fa => totalAccounts.Any(t => t.TradingAccount == fa.FinalTradingAccount))
                            .ToList();
                        }
                        LogUtility.Logger.Logger.Log("lstObj OK", LogType.Debug);
                        var grGroup = this.context.GoldenRecordMsts.Where(g => g.GoldenRecordId == goldenId).ToList();
                        LogUtility.Logger.Logger.Log("grGroup OK", LogType.Debug);
                        EventOptionPositionsWithType tempResult = new EventOptionPositionsWithType();
                    tempResult.EventOptionPositionsModel = (from o in x.DefaultIfEmpty()
                                                            from gr in grGroup.DefaultIfEmpty()
                                                            join a in this.context.ClientPositionDtls on tradingAccnt equals a.TradingAccountNumber + "-" + a.Accounttype into clientPositionDtlGroup
                                                            from clientPositionDtl in clientPositionDtlGroup.Where(a => a.IsActive == 1 && gr.BloombergId == a.BloombergId).DefaultIfEmpty()
                                                            join am in this.context.AccountMsts on tradingAccnt.Split('-')[0] equals am.TradingAccountNumber into actMstGroup
                                                                from actMst in actMstGroup.Where(a => a.IsActive == 1).DefaultIfEmpty()
                                                                select new EventOptionPositionsModel
                                                                {
                                                                    Mt564SemeRef = o?.Mt564SemeRef ?? String.Empty,
                                                                    TradingAccountNumber = tradingAccnt,
                                                                    CDR = actMst?.LegalEntityName ?? "",
                                                                    Position = (clientPositionDtl != null) ? ((positionType != null && positionType.PositionType == "TRAD") ? clientPositionDtl.AggTradeDatePosition : clientPositionDtl.AggSettleDatePosition) : 0,
                                                                    TradePosition = clientPositionDtl?.AggTradeDatePosition ?? 0,
                                                                    SettlePosition = clientPositionDtl?.AggSettleDatePosition ?? 0,
                                                                    TotalElectedPosition = details.Where(c => c.TradingAccount == tradingAccnt && (c.OptionStatus == "INSTRUCTION_ACCEPTED" || c.OptionStatus == "INSTRUCTION_DEFAULT")).Sum(c => c.Qty),
                                                                    TotalUnElectedPosition = (clientPositionDtl != null) ? ((positionType != null && positionType.PositionType == "TRAD") ? clientPositionDtl.AggTradeDatePosition : clientPositionDtl.AggSettleDatePosition) - details.Where(c => c.TradingAccount == tradingAccnt && (c.OptionStatus == "INSTRUCTION_ACCEPTED" || c.OptionStatus == "INSTRUCTION_DEFAULT")).Sum(c => c.Qty) : 0,
                                                                    PendingPosition = details.Where(c => c.TradingAccount == tradingAccnt && c.OptionStatus == "PENDING_INSTRUCTION").Sum(c => c.Qty),
                                                                    PendingCancellation = details.Where(c => c.TradingAccount == tradingAccnt && c.OptionStatus == "PENDING_CANCELLATION").Sum(c => c.Qty),
                                                                    Accounttype = clientPositionDtl?.Accounttype != null ? (String.IsNullOrEmpty(clientPositionDtl.Accounttype) ? "" : this.enumHelper.GetEnumDescription((AccountTypeEnum)Convert.ToInt32(clientPositionDtl.Accounttype))) : this.enumHelper.GetEnumDescription((AccountTypeEnum)int.Parse(tradingAccnt.Substring(tradingAccnt.LastIndexOf('-') + 1, tradingAccnt.Length - (tradingAccnt.LastIndexOf('-') + 1)))),
                                                                    EventOptionPositionDetails = details.Where(c => c.TradingAccount == tradingAccnt).ToList(),
                                                                    SwiftOrEmail = actMst != null ?
                                                                    (actMst.SwiftMessageEnabled != null ?
                                                                        (actMst.SwiftMessageEnabled.ToUpper() == "Y" ?
                                                                            (actMst.EmailEnabled != null ?
                                                                                (actMst.EmailEnabled.ToUpper() == "Y" ? "Swift,Email" : "Swift") :
                                                                                "Swift"
                                                                            ) :
                                                                            (actMst.EmailEnabled != null ?
                                                                                (actMst.EmailEnabled.ToUpper() == "Y" ? "Email" : "none") :
                                                                                "none"
                                                                            )
                                                                        ) :
                                                                        (actMst.EmailEnabled != null ?
                                                                            (actMst.EmailEnabled.ToUpper() == "Y" ? "Email" : "none") :
                                                                            "none"
                                                                        )
                                                                    ) : "",
                                                                    PositionType = positionType?.PositionType,
                                                                    CIBCEntity = actMst?.CibcEntity
                                                                }).Where(x => !string.IsNullOrEmpty(x.CDR)).DistinctBy(a => a.TradingAccountNumber).ToList();
                        LogUtility.Logger.Logger.Log("OK1", LogType.Debug);
                        if (tempResult.EventOptionPositionsModel != null)
                        {
                            if (eventOptionPositionsModel.EventOptionPositionsModel == null)
                            {
                                eventOptionPositionsModel.EventOptionPositionsModel = new List<EventOptionPositionsModel>();
                            }

                            eventOptionPositionsModel.EventOptionPositionsModel.AddRange(tempResult.EventOptionPositionsModel);
                        }

                    });
                    }
                }
                eventOptionPositionsModel.PositionType = positionType.PositionType;

                return eventOptionPositionsModel;
            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                if (ex.InnerException != null)
                {
                    if (!string.IsNullOrEmpty(ex.InnerException.Message))
                        Logger.LogException(ex, LogType.Error, ex.InnerException.Message);
                }
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return eventOptionPositionsModel;
        }

        public PositionCapturedModel GetPositionCapturedDateByGoldenId(int goldenId)
        {
            var positionCapturedDate = this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == goldenId && x.IsActive == 1)
                .Select(
                    x => new
                    {
                        x.PositionFixDate,
                        x.IsPositionCaptured
                    }
                    ).FirstOrDefault();

            PositionCapturedModel objPositionCaptured = new PositionCapturedModel
            {
                IsPositionCaptured = positionCapturedDate.IsPositionCaptured,
                PositionCapturedDate = positionCapturedDate.PositionFixDate
            };

            return objPositionCaptured ?? null;
        }

        public EventConflictResolutionParameter UpdateEventConflictResolution(EventConflictResolutionParameter eventConflictResolution, int userId, string Role)
        {
            try
            {
                Logger.Log($"UpdateEventConflictResolution = User ID : {userId} Role : {Role}", LogType.Info);
                bool conditionalFieldChange = false;
                if (Role != UserRoleConsts.SUPERVISOR && Role != UserRoleConsts.ANALYST && Role != UserRoleConsts.SYSTEM_ADMIN)
                {
                    eventConflictResolution.IsSuccess = false;
                    eventConflictResolution.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NoPermission);
                    eventConflictResolution.MessageId = (int)ResponseCodeMessage.NoPermission;
                    return eventConflictResolution;
                }

                if (eventConflictResolution.IsRequired)
                {
                    CaEventConflict eventConflictMst = this.context.CaEventConflicts.Where(x => x.ConflictId == eventConflictResolution.ConflictId).FirstOrDefault();
                    if (eventConflictMst != null)
                    {
                        bool isLeogAndIsDateAvailable = false;
                        bool isDateCodeUpdated = false;
                        DisplayData displayData = this.linqToDbHelper.GetDisplayDataByGoldenRecordId((int)eventConflictMst.GoldenRecordId);
                        if (eventConflictMst.FieldName == "eventdetail.letterofguaranteeddelivery.flag")
                        {
                            if (Newtonsoft.Json.Linq.JObject.
                                Parse(eventConflictResolution.ResolveValue)["flag"] != null &&
                                Newtonsoft.Json.Linq.JObject.
                                Parse(eventConflictResolution.ResolveValue)["flag"].ToString().ToUpper() == "N")
                            {
                                int totalOptions = displayData.Options.Count;
                                if (totalOptions > 0)
                                {
                                    for (int i = 0; i < totalOptions; i++)
                                    {
                                        string currentOptionNumber = displayData.Options[i].CaOptOptionNumber;
                                        if (currentOptionNumber != "999")
                                        {
                                            if (!String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptDepositoryCoverExpirationDate.ToString())
                                                || !String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptCoverExpirationDate.ToString())
                                                || (displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptDepositoryCoverExpirationDateCode == "ONGO")
                                                || (displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptCoverExpirationDateCode == "ONGO")
                                                )
                                            {
                                                isLeogAndIsDateAvailable = true;
                                                displayData.LetterofGuaranteedDelivery = null;
                                                eventConflictResolution.ResolveValue = null;
                                                eventConflictResolution.Comments = null;
                                                conditionalFieldChange = true;
                                                break;
                                            }
                                            else
                                            {
                                                if (displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptDepositoryCoverExpirationDateCode == "UKWN")
                                                {
                                                    displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptDepositoryCoverExpirationDateCode = null;
                                                    isDateCodeUpdated = true;
                                                }
                                                if (displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptCoverExpirationDateCode == "UKWN")
                                                {
                                                    displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptCoverExpirationDateCode = null;
                                                    isDateCodeUpdated = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if (eventConflictMst.FieldName == "optiondetail.withdrawalallowed.flag")
                        {
                            if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictResolution.ResolveValue)["flag"].ToString().ToUpper() == "N")
                            {
                                if (displayData.Options.Where(x => x.CaOptOptionNumber == eventConflictMst.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodFromDateCode == "UKWN")
                                {
                                    displayData.Options.Where(x => x.CaOptOptionNumber == eventConflictMst.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodFromDateCode = null;
                                    isDateCodeUpdated = true;
                                }

                                if (displayData.Options.Where(x => x.CaOptOptionNumber == eventConflictMst.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodToDateCode == "UKWN")
                                {
                                    displayData.Options.Where(x => x.CaOptOptionNumber == eventConflictMst.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodToDateCode = null;
                                    isDateCodeUpdated = true;
                                }
                            }

                        }

                        eventConflictMst.ResolveBy = userId;
                        eventConflictMst.EntryBy = userId;
                        eventConflictMst.EntryDtTime = DateTime.Now;
                        eventConflictMst.EntryDtTimeUtc = DateTime.UtcNow;
                        eventConflictMst.ResolveType = eventConflictResolution.ResolveType;
                        eventConflictMst.ResolveValue = eventConflictResolution.ResolveValue;
                        eventConflictMst.FieldStatus = isLeogAndIsDateAvailable ? 2 : eventConflictMst.FieldStatus;
                        eventConflictMst.ReviewStatus = isLeogAndIsDateAvailable ? Convert.ToByte(1) : eventConflictResolution.ReviewStatus;
                        eventConflictMst.Comments = eventConflictResolution.Comments;

                        if (eventConflictMst.FieldName == "optiondetail.withdrawalallowed.flag")
                        {
                            CaEventConflict withdrawFrom = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.revocabilityperiod.fromdatetime" && x.OptionNumber == eventConflictMst.OptionNumber).FirstOrDefault();
                            CaEventConflict withdrawTo = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.revocabilityperiod.todatetime" && x.OptionNumber == eventConflictMst.OptionNumber).FirstOrDefault();

                            if (withdrawFrom == null)
                            {
                                CaEventConflict caEventConflict = new CaEventConflict();
                                caEventConflict.GoldenRecordId = eventConflictMst.GoldenRecordId;
                                caEventConflict.FieldName = "optiondetail.revocabilityperiod.fromdatetime";
                                caEventConflict.OptionNumber = eventConflictMst.OptionNumber;
                                caEventConflict.MovementId = string.Empty;
                                caEventConflict.ExistingSource = eventConflictMst.ExistingSource;
                                caEventConflict.ClientValue = "";
                                caEventConflict.NewEventId = 0;
                                caEventConflict.NewEventSource = "";
                                caEventConflict.NewEventValue = "";
                                caEventConflict.NewEventOptionNumber = "";
                                caEventConflict.NewEventMovementId = "";
                                caEventConflict.IsActive = 1;
                                caEventConflict.EntryBy = 9990;
                                caEventConflict.EntryDtTime = DateTime.Now;
                                caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                                this.context.CaEventConflicts.Add(caEventConflict);
                                this.context.SaveChanges();
                                withdrawFrom = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.revocabilityperiod.fromdatetime" && x.OptionNumber == eventConflictMst.OptionNumber).FirstOrDefault();
                            }

                            if (withdrawTo == null)
                            {
                                CaEventConflict caEventConflict = new CaEventConflict();
                                caEventConflict.GoldenRecordId = eventConflictMst.GoldenRecordId;
                                caEventConflict.FieldName = "optiondetail.revocabilityperiod.todatetime";
                                caEventConflict.OptionNumber = eventConflictMst.OptionNumber;
                                caEventConflict.MovementId = string.Empty;
                                caEventConflict.ExistingSource = eventConflictMst.ExistingSource;
                                caEventConflict.ClientValue = "";
                                caEventConflict.NewEventId = 0;
                                caEventConflict.NewEventSource = "";
                                caEventConflict.NewEventValue = "";
                                caEventConflict.NewEventOptionNumber = "";
                                caEventConflict.NewEventMovementId = "";
                                caEventConflict.IsActive = 1;
                                caEventConflict.EntryBy = 9990;
                                caEventConflict.EntryDtTime = DateTime.Now;
                                caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                                this.context.CaEventConflicts.Add(caEventConflict);
                                this.context.SaveChanges();
                                withdrawTo = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.revocabilityperiod.todatetime" && x.OptionNumber == eventConflictMst.OptionNumber).FirstOrDefault();
                            }

                            if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictResolution.ResolveValue)["flag"].ToString().ToUpper() == "Y")
                            {
                                if (!String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == eventConflictMst.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodFrom.ToString())
                                    && (withdrawFrom.ReviewStatus == (byte)EventReviewStatus.SystemResolved || withdrawFrom.ReviewStatus == (byte)EventReviewStatus.UserResolved))
                                {
                                    withdrawFrom.FieldStatus = 0;
                                    withdrawFrom.ReviewStatus = 3;
                                }
                                else if (String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == eventConflictMst.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodFrom.ToString())
                                    && String.IsNullOrEmpty(withdrawFrom.ResolveValue))
                                {
                                    withdrawFrom.ResolveValue = "{\"fromdatecode\":\"UKWN\",\"qualifier\":\"REVO\"}";
                                    withdrawFrom.FieldStatus = 2;
                                    withdrawFrom.ReviewStatus = 2;
                                    conditionalFieldChange = true;
                                }
                                else if (!String.IsNullOrEmpty(withdrawFrom.ResolveValue) && withdrawFrom.ResolveValue.ToLower().Contains("fromdatecode"))
                                {
                                    withdrawFrom.FieldStatus = 2;
                                    withdrawFrom.ReviewStatus = 2;
                                    conditionalFieldChange = true;
                                }
                                else
                                {
                                    withdrawFrom.FieldStatus = 0;
                                    withdrawFrom.ReviewStatus = 3;
                                }


                                if (!String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == eventConflictMst.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodTo.ToString())
                                    && withdrawTo.ReviewStatus != (byte)EventReviewStatus.InReview)
                                {
                                    withdrawTo.FieldStatus = 0;
                                    withdrawTo.ReviewStatus = 3;
                                }
                                else if (String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == eventConflictMst.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodTo.ToString())
                                    && String.IsNullOrEmpty(withdrawTo.ResolveValue))
                                {
                                    withdrawTo.FieldStatus = 2;
                                    withdrawTo.ReviewStatus = 1;
                                    conditionalFieldChange = true;
                                }
                                else if (!String.IsNullOrEmpty(withdrawTo.ResolveValue) && withdrawTo.ResolveValue.ToLower().Contains("fromdatecode"))
                                {
                                    withdrawTo.FieldStatus = 2;
                                    withdrawTo.ReviewStatus = 1;
                                    conditionalFieldChange = true;
                                }
                                else
                                {
                                    withdrawTo.FieldStatus = 0;
                                    withdrawTo.ReviewStatus = 3;
                                }
                            }
                            else
                            {
                                withdrawFrom.FieldStatus = 0;
                                withdrawFrom.ReviewStatus = 3;
                                withdrawTo.FieldStatus = 0;
                                withdrawTo.ReviewStatus = 3;
                                withdrawFrom.ResolveValue = null;
                                withdrawFrom.ResolveType = null;
                                withdrawFrom.ResolveBy = null;
                                withdrawFrom.Comments = null;
                                withdrawTo.ResolveValue = null;
                                withdrawTo.ResolveType = null;
                                withdrawTo.ResolveBy = null;
                                withdrawTo.Comments = null;
                            }
                            this.context.CaEventConflicts.Update(withdrawTo);
                            this.context.CaEventConflicts.Update(withdrawFrom);
                            this.context.SaveChanges();
                        }

                        if (eventConflictMst.FieldName == "eventdetail.letterofguaranteeddelivery.flag" && !isLeogAndIsDateAvailable &&
                            Newtonsoft.Json.Linq.JObject.Parse(eventConflictResolution.ResolveValue)["flag"].ToString().ToUpper() != "NA")
                        {
                            int totalOptions = displayData.Options.Count;
                            if (totalOptions > 0)
                            {
                                for (int i = 0; i < totalOptions; i++)
                                {
                                    string currentOptionNumber = displayData.Options[i].CaOptOptionNumber;
                                    if (currentOptionNumber != "999")
                                    {
                                        CaEventConflict CaOptDepositoryCoverExpirationDate = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.depositorycoverexpirationdate.cadatetime" && x.OptionNumber == currentOptionNumber).FirstOrDefault();
                                        CaEventConflict CaOptCoverExpirationDate = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.coverexpirationdate.cadatetime" && x.OptionNumber == currentOptionNumber).FirstOrDefault();

                                        if (CaOptDepositoryCoverExpirationDate == null)
                                        {
                                            CaEventConflict caEventConflict = new CaEventConflict();
                                            caEventConflict.GoldenRecordId = eventConflictMst.GoldenRecordId;
                                            caEventConflict.FieldName = "optiondetail.depositorycoverexpirationdate.cadatetime";
                                            caEventConflict.OptionNumber = currentOptionNumber;
                                            caEventConflict.MovementId = string.Empty;
                                            caEventConflict.ExistingSource = eventConflictMst.ExistingSource;
                                            caEventConflict.ClientValue = "";
                                            caEventConflict.NewEventId = 0;
                                            caEventConflict.NewEventSource = "";
                                            caEventConflict.NewEventValue = "";
                                            caEventConflict.NewEventOptionNumber = "";
                                            caEventConflict.NewEventMovementId = "";
                                            caEventConflict.IsActive = 1;
                                            caEventConflict.EntryBy = 9990;
                                            caEventConflict.EntryDtTime = DateTime.Now;
                                            caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                                            this.context.CaEventConflicts.Add(caEventConflict);
                                            this.context.SaveChanges();
                                            CaOptDepositoryCoverExpirationDate = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.depositorycoverexpirationdate.cadatetime" && x.OptionNumber == currentOptionNumber).FirstOrDefault();
                                        }

                                        if (CaOptCoverExpirationDate == null)
                                        {
                                            CaEventConflict caEventConflict = new CaEventConflict();
                                            caEventConflict.GoldenRecordId = eventConflictMst.GoldenRecordId;
                                            caEventConflict.FieldName = "optiondetail.coverexpirationdate.cadatetime";
                                            caEventConflict.OptionNumber = currentOptionNumber;
                                            caEventConflict.MovementId = string.Empty;
                                            caEventConflict.ExistingSource = eventConflictMst.ExistingSource;
                                            caEventConflict.ClientValue = "";
                                            caEventConflict.NewEventId = 0;
                                            caEventConflict.NewEventSource = "";
                                            caEventConflict.NewEventValue = "";
                                            caEventConflict.NewEventOptionNumber = "";
                                            caEventConflict.NewEventMovementId = "";
                                            caEventConflict.IsActive = 1;
                                            caEventConflict.EntryBy = 9990;
                                            caEventConflict.EntryDtTime = DateTime.Now;
                                            caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                                            this.context.CaEventConflicts.Add(caEventConflict);
                                            this.context.SaveChanges();
                                            CaOptCoverExpirationDate = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.coverexpirationdate.cadatetime" && x.OptionNumber == currentOptionNumber).FirstOrDefault();
                                        }


                                        if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictResolution.ResolveValue)["flag"].ToString().ToUpper() == "Y")
                                        {
                                            if (!String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptDepositoryCoverExpirationDate.ToString())
                                                && (CaOptDepositoryCoverExpirationDate.ReviewStatus == (byte)EventReviewStatus.SystemResolved || CaOptDepositoryCoverExpirationDate.ReviewStatus == (byte)EventReviewStatus.UserResolved))
                                            {
                                                CaOptDepositoryCoverExpirationDate.FieldStatus = 0;
                                                CaOptDepositoryCoverExpirationDate.ReviewStatus = 3;
                                            }
                                            else if (String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptDepositoryCoverExpirationDate.ToString())
                                                && String.IsNullOrEmpty(CaOptDepositoryCoverExpirationDate.ResolveValue)
                                                && String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptDepositoryCoverExpirationDateCode))
                                            {
                                                CaOptDepositoryCoverExpirationDate.FieldStatus = 2;
                                                CaOptDepositoryCoverExpirationDate.ReviewStatus = 1;
                                                conditionalFieldChange = true;
                                            }
                                            else if (String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptDepositoryCoverExpirationDate.ToString())
                                                && String.IsNullOrEmpty(CaOptDepositoryCoverExpirationDate.ResolveValue)
                                                && (displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptDepositoryCoverExpirationDateCode == "UKWN"))
                                            {
                                                CaOptDepositoryCoverExpirationDate.FieldStatus = 2;
                                                CaOptDepositoryCoverExpirationDate.ReviewStatus = 1;
                                                conditionalFieldChange = true;
                                            }
                                            else if (!String.IsNullOrEmpty(CaOptDepositoryCoverExpirationDate.ResolveValue) &&
                                                CaOptDepositoryCoverExpirationDate.ResolveValue.ToLower().Contains("cadatetime") &&
                                                CaOptDepositoryCoverExpirationDate.ReviewStatus != (byte)EventReviewStatus.InReview)
                                            {
                                                CaOptDepositoryCoverExpirationDate.FieldStatus = 2;
                                                CaOptDepositoryCoverExpirationDate.ReviewStatus = 1;
                                                conditionalFieldChange = true;
                                            }
                                            else if (!String.IsNullOrEmpty(CaOptCoverExpirationDate.ResolveValue) &&
                                              CaOptDepositoryCoverExpirationDate.ResolveValue.ToLower().Contains("cadatetime") &&
                                              CaOptDepositoryCoverExpirationDate.ReviewStatus == (byte)EventReviewStatus.InReview)
                                            {
                                                conditionalFieldChange = true;
                                            }
                                            else
                                            {
                                                CaOptDepositoryCoverExpirationDate.FieldStatus = 0;
                                                CaOptDepositoryCoverExpirationDate.ReviewStatus = 3;
                                            }

                                            if (!String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptCoverExpirationDate.ToString())
                                                && CaOptCoverExpirationDate.ReviewStatus != (byte)EventReviewStatus.InReview)
                                            {
                                                CaOptCoverExpirationDate.FieldStatus = 0;
                                                CaOptCoverExpirationDate.ReviewStatus = 3;
                                            }
                                            else if (String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptCoverExpirationDate.ToString())
                                                && String.IsNullOrEmpty(CaOptCoverExpirationDate.ResolveValue)
                                                && String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptCoverExpirationDateCode))
                                            {
                                                CaOptCoverExpirationDate.FieldStatus = 2;
                                                CaOptCoverExpirationDate.ReviewStatus = 1;
                                                conditionalFieldChange = true;
                                            }
                                            else if (String.IsNullOrEmpty(displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptCoverExpirationDate.ToString())
                                                && String.IsNullOrEmpty(CaOptCoverExpirationDate.ResolveValue)
                                                && (displayData.Options.Where(x => x.CaOptOptionNumber == currentOptionNumber).FirstOrDefault().CaOptCoverExpirationDateCode == "UKWN"))
                                            {
                                                CaOptCoverExpirationDate.FieldStatus = 2;
                                                CaOptCoverExpirationDate.ReviewStatus = 1;
                                                conditionalFieldChange = true;
                                            }
                                            else if (!String.IsNullOrEmpty(CaOptCoverExpirationDate.ResolveValue) &&
                                                CaOptCoverExpirationDate.ResolveValue.ToLower().Contains("cadatetime") &&
                                                CaOptCoverExpirationDate.ReviewStatus != (byte)EventReviewStatus.InReview)
                                            {
                                                CaOptCoverExpirationDate.FieldStatus = 2;
                                                CaOptCoverExpirationDate.ReviewStatus = 1;
                                                conditionalFieldChange = true;
                                            }
                                            else if (!String.IsNullOrEmpty(CaOptCoverExpirationDate.ResolveValue) &&
                                                CaOptCoverExpirationDate.ResolveValue.ToLower().Contains("cadatetime") &&
                                                CaOptCoverExpirationDate.ReviewStatus == (byte)EventReviewStatus.InReview)
                                            {
                                                conditionalFieldChange = true;
                                            }
                                            else
                                            {
                                                CaOptCoverExpirationDate.FieldStatus = 0;
                                                CaOptCoverExpirationDate.ReviewStatus = 3;
                                            }
                                        }
                                        else
                                        {
                                            CaOptDepositoryCoverExpirationDate.FieldStatus = 0;
                                            CaOptDepositoryCoverExpirationDate.ReviewStatus = 3;
                                            CaOptCoverExpirationDate.FieldStatus = 0;
                                            CaOptCoverExpirationDate.ReviewStatus = 3;
                                            CaOptDepositoryCoverExpirationDate.ResolveValue = null;
                                            CaOptDepositoryCoverExpirationDate.ResolveType = null;
                                            CaOptDepositoryCoverExpirationDate.ResolveBy = null;
                                            CaOptDepositoryCoverExpirationDate.Comments = null;
                                            CaOptCoverExpirationDate.ResolveValue = null;
                                            CaOptCoverExpirationDate.ResolveType = null;
                                            CaOptCoverExpirationDate.ResolveBy = null;
                                            CaOptCoverExpirationDate.Comments = null;
                                        }
                                        this.context.CaEventConflicts.Update(CaOptDepositoryCoverExpirationDate);
                                        this.context.CaEventConflicts.Update(CaOptCoverExpirationDate);
                                        this.context.SaveChanges();
                                    }
                                }
                            }
                        }

                        if (IsPeriodField(eventConflictMst.FieldName))
                        {
                            switch (eventConflictMst.FieldName)
                            {
                                case "optiondetail.revocabilityperiod.fromdatetime":
                                    if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["fromdatecode"] != null && Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["fromdatecode"].ToString().ToUpper() == "NA")
                                    {
                                        CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.revocabilityperiod.todatetime" && x.OptionNumber == eventConflictMst.OptionNumber).FirstOrDefault();
                                        if (objTemp != null)
                                        {
                                            var finalString = "{\"ToDateCode\":\"NA\",\"qualifier\":\"REVO\"}";
                                            objTemp.ResolveValue = finalString;
                                            objTemp.Comments = eventConflictMst.Comments;
                                            objTemp.ReviewStatus = 2;
                                            this.context.CaEventConflicts.Update(objTemp);
                                        }
                                    }
                                    break;
                                case "optiondetail.revocabilityperiod.todatetime":
                                    if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["ToDateCode"] != null && Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["ToDateCode"].ToString().ToUpper() == "NA")
                                    {
                                        CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.revocabilityperiod.fromdatetime" && x.OptionNumber == eventConflictMst.OptionNumber).FirstOrDefault();
                                        if (objTemp != null)
                                        {
                                            var finalString = "{\"fromdatecode\":\"NA\",\"qualifier\":\"REVO\"}";
                                            objTemp.ResolveValue = finalString;
                                            objTemp.Comments = eventConflictMst.Comments;
                                            objTemp.ReviewStatus = 2;
                                            this.context.CaEventConflicts.Update(objTemp);
                                        }
                                    }
                                    break;
                                case "eventdetail.claimperiod.fromdatetime":
                                    if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["fromdatecode"] != null && Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["fromdatecode"].ToString().ToUpper() == "NA")
                                    {
                                        CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "eventdetail.claimperiod.todatetime").FirstOrDefault();
                                        if (objTemp != null)
                                        {
                                            var finalString = "{\"ToDateCode\":\"NA\",\"qualifier\":\"CLCP\"}";
                                            objTemp.ResolveValue = finalString;
                                            objTemp.Comments = eventConflictMst.Comments;
                                            objTemp.ReviewStatus = 2;
                                            this.context.CaEventConflicts.Update(objTemp);
                                        }
                                    }
                                    break;
                                case "eventdetail.claimperiod.todatetime":
                                    if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["ToDateCode"] != null && Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["ToDateCode"].ToString().ToUpper() == "NA")
                                    {
                                        CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "eventdetail.claimperiod.fromdatetime").FirstOrDefault();
                                        if (objTemp != null)
                                        {
                                            var finalString = "{\"fromdatecode\":\"NA\",\"qualifier\":\"CLCP\"}";
                                            objTemp.ResolveValue = finalString;
                                            objTemp.Comments = eventConflictMst.Comments;
                                            objTemp.ReviewStatus = 2;
                                            this.context.CaEventConflicts.Update(objTemp);
                                        }
                                    }
                                    break;
                                case "optiondetail.periodofaction.fromdatetime":
                                    if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["fromdatecode"] != null && Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["fromdatecode"].ToString().ToUpper() == "NA")
                                    {
                                        CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.periodofaction.todatetime" && x.OptionNumber == eventConflictMst.OptionNumber).FirstOrDefault();
                                        if (objTemp != null)
                                        {
                                            var finalString = "{\"ToDateCode\":\"NA\",\"qualifier\":\"PWAL\"}";
                                            objTemp.ResolveValue = finalString;
                                            objTemp.Comments = eventConflictMst.Comments;
                                            objTemp.ReviewStatus = 2;
                                            this.context.CaEventConflicts.Update(objTemp);
                                        }
                                    }
                                    break;
                                case "optiondetail.periodofaction.todatetime":
                                    if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["ToDateCode"] != null && Newtonsoft.Json.Linq.JObject.Parse(eventConflictMst.ResolveValue)["ToDateCode"].ToString().ToUpper() == "NA")
                                    {
                                        CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.FieldName == "optiondetail.periodofaction.fromdatetime" && x.OptionNumber == eventConflictMst.OptionNumber).FirstOrDefault();
                                        if (objTemp != null)
                                        {
                                            var finalString = "{\"fromdatecode\":\"NA\",\"qualifier\":\"PWAL\"}";
                                            objTemp.ResolveValue = finalString;
                                            objTemp.Comments = eventConflictMst.Comments;
                                            objTemp.ReviewStatus = 2;
                                            this.context.CaEventConflicts.Update(objTemp);
                                        }
                                    }
                                    break;
                                default:
                                    break;
                            }
                        }

                        if (isLeogAndIsDateAvailable || isDateCodeUpdated)
                        {
                            this.linqToDbHelper.UpdateMT564Message(displayData);
                        }

                        if (eventConflictMst.FieldName == "optiondetail.optionstatus.indicator")
                        {
                            if (Newtonsoft.Json.Linq.JObject.Parse(eventConflictResolution.ResolveValue)["indicator"].ToString().ToUpper() == "CANC")
                            {
                                List<CaEventConflict> allMissingConflicts = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == eventConflictMst.GoldenRecordId && x.OptionNumber == eventConflictMst.OptionNumber && (
                                (x.FieldStatus == Convert.ToInt32(EventFieldStatus.Conflict) ||
                                x.FieldStatus == Convert.ToInt32(EventFieldStatus.Incomplete)) &&
                                x.ReviewStatus == Convert.ToInt32(EventReviewStatus.Open))).ToList();
                                allMissingConflicts.ForEach(missingConflict =>
                                {
                                    missingConflict.ResolveValue = ResolveString(missingConflict.FieldName);
                                    missingConflict.ReviewStatus = Convert.ToByte(EventReviewStatus.InReview);
                                    missingConflict.ResolveType = "CAAPS";
                                    conditionalFieldChange = true;
                                    this.context.CaEventConflicts.Update(missingConflict);
                                });
                            }
                        }
                        /*
                            Redmine : 23933 new_caaps_timezone.
                            Below condition checks if it is datetime field of corporate action options than we add the utc indicator value of given datetime value in conflict status.
                        */
                        if (eventConflictMst.FieldName == "optiondetail.responsedeadlinedate.cadatetime" || eventConflictMst.FieldName == "optiondetail.earlyresponsedeadlinedate.cadatetime" || eventConflictMst.FieldName == "optiondetail.coverexpirationdate.cadatetime" || eventConflictMst.FieldName == "optiondetail.depositorycoverexpirationdate.cadatetime" || eventConflictMst.FieldName == "optiondetail.expirydate.cadatetime" || eventConflictMst.FieldName == "optiondetail.marketdeadlinedate.cadatetime" || eventConflictMst.FieldName == "optiondetail.protectdate.cadatetime")
                        {
                            eventConflictMst.ResolveValue = addUTCIndicator(eventConflictMst.ResolveValue,true);
                        }
                         /*
                            Redmine : 23933 new_caaps_timezone.
                            Below condition checks if it is period field than we add the utc indicator value with static Eastern value.
                        */
                        if(eventConflictMst.FieldName == "optiondetail.revocabilityperiod.todatetime" || eventConflictMst.FieldName == "optiondetail.periodofaction.todatetime")   
                        {
                            eventConflictMst.ResolveValue = addUTCIndicator(eventConflictMst.ResolveValue, false);
                        }
                        this.context.SaveChanges();
                        eventConflictResolution.IsSuccess = true;
                        eventConflictResolution.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Updated);
                        eventConflictResolution.MessageId = (int)ResponseCodeMessage.Updated;
                        Logger.Log($"UpdateEventConflictResolution UpdateWorkFlowStatus 1904 = Golden Record ID : {eventConflictMst.GoldenRecordId}", LogType.Info);
                        this.UpdateWorkFlowStatus(eventConflictMst.GoldenRecordId, Role, userId, conditionalFieldChange);
                        SaveInActiveDate(eventConflictMst.GoldenRecordId);

                        sendEventNotification(
                            $"Conflict Resolved for type: {eventConflictResolution.ResolveType} with value {eventConflictResolution.ResolveValue} ,Resolved by {userId}",
                            "CONFLICT_RESOLVED",
                             new
                             {
                                 GoldenId = eventConflictMst.GoldenRecordId
                             });
                    }
                    else
                    {
                        CaEventConflict caEventConflict = new CaEventConflict();
                        caEventConflict.GoldenRecordId = eventConflictResolution.GoldenRecordId;
                        caEventConflict.FieldName = eventConflictResolution.FieldName;
                        caEventConflict.OptionNumber = eventConflictResolution.OptionNumber;
                        caEventConflict.MovementId = eventConflictResolution.MovementNumber;
                        caEventConflict.ExistingSource = eventConflictResolution.Source;
                        caEventConflict.ClientValue = "";
                        caEventConflict.NewEventId = 0;
                        caEventConflict.NewEventSource = "";
                        caEventConflict.NewEventValue = "";
                        caEventConflict.NewEventOptionNumber = "";
                        caEventConflict.NewEventMovementId = "";
                        caEventConflict.ResolveBy = userId;
                        caEventConflict.ResolveType = eventConflictResolution.ResolveType;
                        caEventConflict.ResolveValue = eventConflictResolution.ResolveValue;
                        caEventConflict.FieldStatus = eventConflictResolution.FieldStatus;
                        caEventConflict.ReviewStatus = eventConflictResolution.ReviewStatus;
                        caEventConflict.Comments = eventConflictResolution.Comments;
                        caEventConflict.IsActive = 1;
                        caEventConflict.EntryBy = 9990;
                        caEventConflict.EntryDtTime = DateTime.Now;
                        caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                        this.context.CaEventConflicts.Add(caEventConflict);
                        this.context.SaveChanges();
                        eventConflictResolution.IsSuccess = true;
                        eventConflictResolution.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Updated);
                        eventConflictResolution.MessageId = (int)ResponseCodeMessage.Updated;
                        Logger.Log($"UpdateEventConflictResolution UpdateWorkFlowStatus 1944 = Golden Record ID : {caEventConflict.GoldenRecordId}", LogType.Info);
                        this.UpdateWorkFlowStatus(caEventConflict.GoldenRecordId, Role, userId, conditionalFieldChange);
                    }
                }
                else
                {
                    CaEventConflict eventConflictMst = this.context.CaEventConflicts.Where(x => x.ConflictId == eventConflictResolution.ConflictId).FirstOrDefault();
                    if (eventConflictMst != null)
                    {
                        DisplayData displayData = this.linqToDbHelper.GetDisplayDataByGoldenRecordId((int)eventConflictMst.GoldenRecordId);
                        displayData.Options.ForEach(option =>
                        {
                            if (option.CaOptOptionNumber == eventConflictMst.OptionNumber)
                            {
                                if (eventConflictMst.FieldName == "optiondetail.depositorycoverexpirationdate.cadatetime")
                                {
                                    if (eventConflictResolution.ResolveValue.Contains("cadatetime"))
                                    {
                                        option.CaOptDepositoryCoverExpirationDate = Convert.ToDateTime(Newtonsoft.Json.Linq.JObject.Parse(eventConflictResolution.ResolveValue)["cadatetime"].ToString());
                                    }
                                    if (eventConflictResolution.ResolveValue.Contains("datecode"))
                                    {
                                        option.CaOptDepositoryCoverExpirationDateCode = Newtonsoft.Json.Linq.JObject.Parse(eventConflictResolution.ResolveValue)["datecode"].ToString();
                                    }

                                }
                                else if (eventConflictMst.FieldName == "optiondetail.coverexpirationdate.cadatetime")
                                {
                                    if (eventConflictResolution.ResolveValue.Contains("cadatetime"))
                                    {
                                        option.CaOptCoverExpirationDate = Convert.ToDateTime(Newtonsoft.Json.Linq.JObject.Parse(eventConflictResolution.ResolveValue)["cadatetime"].ToString());
                                    }
                                    if (eventConflictResolution.ResolveValue.Contains("datecode"))
                                    {
                                        option.CaOptCoverExpirationDateCode = Newtonsoft.Json.Linq.JObject.Parse(eventConflictResolution.ResolveValue)["datecode"].ToString();
                                    }
                                }
                            }
                        });
                        this.linqToDbHelper.UpdateMT564Message(displayData);
                        eventConflictMst.EntryBy = userId;
                        eventConflictMst.EntryDtTime = DateTime.Now;
                        eventConflictMst.EntryDtTimeUtc = DateTime.UtcNow;
                        eventConflictMst.FieldStatus = 0;
                        eventConflictMst.ReviewStatus = 3;
                        eventConflictMst.Comments = eventConflictResolution.Comments;
                        this.context.CaEventConflicts.Update(eventConflictMst);
                        this.context.SaveChanges();
                        eventConflictResolution.IsSuccess = true;
                        eventConflictResolution.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Updated);
                        eventConflictResolution.MessageId = (int)ResponseCodeMessage.Updated;
                        Logger.Log($"UpdateEventConflictResolution UpdateWorkFlowStatus 1994 = Golden Record ID : {eventConflictMst.GoldenRecordId}", LogType.Info);
                        this.UpdateWorkFlowStatus(eventConflictMst.GoldenRecordId, Role, userId, conditionalFieldChange);
                        SaveInActiveDate(eventConflictMst.GoldenRecordId);

                        sendEventNotification(
                            $"Conflict Resolved for type: {eventConflictResolution.ResolveType} with value {eventConflictResolution.ResolveValue} ,Resolved by {userId}",
                            "CONFLICT_RESOLVED",
                             new
                             {
                                 GoldenId = eventConflictMst.GoldenRecordId
                             });
                    }
                    else
                    {
                        CaEventConflict caEventConflict = new CaEventConflict();
                        caEventConflict.GoldenRecordId = eventConflictResolution.GoldenRecordId;
                        caEventConflict.FieldName = eventConflictResolution.FieldName;
                        caEventConflict.OptionNumber = eventConflictResolution.OptionNumber;
                        caEventConflict.MovementId = eventConflictResolution.MovementNumber;
                        caEventConflict.ExistingSource = eventConflictResolution.Source;
                        caEventConflict.ClientValue = "";
                        caEventConflict.NewEventId = 0;
                        caEventConflict.NewEventSource = "";
                        caEventConflict.NewEventValue = "";
                        caEventConflict.NewEventOptionNumber = "";
                        caEventConflict.NewEventMovementId = "";
                        caEventConflict.ResolveBy = userId;
                        caEventConflict.ResolveType = eventConflictResolution.ResolveType;
                        caEventConflict.ResolveValue = eventConflictResolution.ResolveValue;
                        caEventConflict.FieldStatus = eventConflictResolution.FieldStatus;
                        caEventConflict.ReviewStatus = eventConflictResolution.ReviewStatus;
                        caEventConflict.Comments = eventConflictResolution.Comments;
                        caEventConflict.IsActive = 1;
                        caEventConflict.EntryBy = 9990;
                        caEventConflict.EntryDtTime = DateTime.Now;
                        caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                        this.context.CaEventConflicts.Add(caEventConflict);
                        this.context.SaveChanges();
                        eventConflictResolution.IsSuccess = true;
                        eventConflictResolution.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Updated);
                        eventConflictResolution.MessageId = (int)ResponseCodeMessage.Updated;
                        this.UpdateWorkFlowStatus(caEventConflict.GoldenRecordId, Role, userId, conditionalFieldChange);
                    }
                }
            }
            catch (Exception ex)
            {
                eventConflictResolution.IsSuccess = false;
                eventConflictResolution.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InvalidData);
                eventConflictResolution.MessageId = (int)ResponseCodeMessage.InvalidData;
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return eventConflictResolution;
        }

        public string addUTCIndicator(string resolveValue, bool isCaField)
        {
       
            try
            {
                string jsonString = resolveValue;
                dynamic jsonObject = JObject.Parse(jsonString);
                string cadatetimeString = null;
                if(isCaField)
                {
                    cadatetimeString = jsonObject.cadatetime;
                }else
                {
                    cadatetimeString = jsonObject.ToDateTime;
                }
                DateTime cadatetime;
                string[] formats = { "yyyy-MM-ddTHH:mm:ss.fffZ", "MM/dd/yyyy HH:mm:ss" };
                if (DateTime.TryParseExact(cadatetimeString, formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out cadatetime))
                {
                    if(cadatetime.ToString("HHmmss") != "000000")
                    {
                        string indicator = this.linqToDbHelper.UTCHelper(cadatetime);
                        jsonObject.utcindicator = indicator;
                        jsonString = jsonObject.ToString();
                        return jsonString;

                    }
                }
                return resolveValue;
            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                return resolveValue;
            }
        }

        public void SaveInActiveDate(long goldenRecordId)
        {
            //IRD Logic
            GoldenRecordMst g = this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == goldenRecordId).FirstOrDefault();
            if (g != null)
            {
                try
                {
                    string matchDateData = System.IO.File.ReadAllText("./MatchDates.json", Encoding.UTF8);
                    var dateField = System.Text.Json.JsonSerializer.Deserialize<List<MatchDateModel>>(matchDateData)
                                                        .Find(a => a.EventName == g.EventName && a.EventMVC == g.EventMvc);

                    CaapsLinqToDB.DBModels.MT564Message message = this.linqToDbHelper.GetEventDetailsByGolderRecordId(goldenRecordId);
                    DateTime? matchDate = this.linqToDbHelper.setInactiveDateHelper(message, dateField.Qualifier);
                    DateTime? responseDeadlineDate = this.linqToDbHelper.setInactiveDateHelper(message, "RDDT");
                    DateTime? earlyResponseDeadlineDate = this.linqToDbHelper.setInactiveDateHelper(message, "EARD");

                    List<DateTime> irdList = new List<DateTime>();
                    irdList.Add(g.ReviewByDate.GetValueOrDefault());
                    irdList.Add(matchDate.GetValueOrDefault());
                    irdList.Add(responseDeadlineDate.GetValueOrDefault());
                    irdList.Add(earlyResponseDeadlineDate.GetValueOrDefault());
                    DateTime? irdDate = irdList.Max();
                    DateTime? prevInactiveDate = g.InactiveDate;

                    bool isOngoingPaymentDate = this.linqToDbHelper.checkDateIsOngoing(message, "PAYD");
                    if (isOngoingPaymentDate && dateField.Qualifier == "PAYD")
                    {
                        irdDate = default(DateTime);
                    }

                    if (irdDate.GetValueOrDefault() != default(DateTime) && irdDate != null)
                    {
                        List<DateTime> latestIrds = new List<DateTime>();
                        latestIrds.Add(irdDate.GetValueOrDefault());
                        latestIrds.Add(DateTime.UtcNow);
                        var inactiveDays = (from cg in this.context.CaEventConfigs
                                            join cem in this.context.CaEventTypeMsts on cg.CaEventTypeId equals cem.CaEventTypeId
                                            join ce in this.context.CaEventMsts on cg.CaEventMstId equals ce.CaEventMstId
                                            where ce.CaEventCode == g.EventName && cem.CaEventType == g.EventMvc
                                            select cg.InactiveDays).FirstOrDefault();
                        g.InactiveDate = latestIrds.Max().AddDays(inactiveDays).Date;
                        g.IsActive = 1;
                    }
                    else
                    {
                        g.InactiveDate = g.GoldenRecordCreateDtTimeUtc.GetValueOrDefault().AddDays(365).Date;
                    }

                    if(prevInactiveDate != null && prevInactiveDate > g.InactiveDate)
                    {
                        g.InactiveDate = prevInactiveDate;
                    }

                    this.context.SaveChanges();
                }
                catch (Exception ex)
                {
                    dynamic logs = new ExpandoObject();
                    logs.StackTrace = ex.StackTrace;
                    Logger.LogException(ex, LogType.Error, logs);
                    this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
                }
            }
            //IRD Logic end
        }



        public void sendEventNotification(string message, string action, dynamic additionalDetails)
        {
            NotificationModel notificationModel = new NotificationModel();
            notificationModel.GUID = Guid.NewGuid().ToString();
            notificationModel.DateTime = DateTime.UtcNow;
            notificationModel.Message = message; //;
            notificationModel.Link = string.Empty;
            notificationModel.Action = action;// ;
            notificationModel.AdditionalDetails = additionalDetails;
            notificationModel.Severity = "INFORMATION";
            notificationModel.Priority = "NORMAL";
            notificationModel.Component = "WEB_SERVER";
            notificationModel.Type = "APP";
            notificationModel.UpdateUI = true;
            this.solaceMessageListener.SendToTopic(this.solaceSettings.ListnerTopicName, JsonConvert.SerializeObject(notificationModel));
        }


        public void UpdateWorkFlowStatus(long golderRecordId, string Role, int userId, bool conditionalFieldChange = false,bool fromAddOrCloneOptionOrMovementAction = false)
        {
            try
            {
                Logger.Log($"UpdateWorkFlowStatus Golden Record ID : {golderRecordId} Role : {Role} User ID : {userId} Conditional Field Change : {conditionalFieldChange}", LogType.Info);

                List<CaEventConflict> conflicts = this.context.CaEventConflicts.Where(c => c.GoldenRecordId == golderRecordId).ToList();

                CaEventConflict c = conflicts.Find(x => (x.FieldStatus == (int)EventFieldStatus.Incomplete || x.FieldStatus == (int)EventFieldStatus.Conflict) && x.ReviewStatus == (int)EventReviewStatus.Open);

                if (c == null)
                {
                    GoldenRecordMst g = this.context.GoldenRecordMsts.Where(gr => gr.GoldenRecordId == golderRecordId).FirstOrDefault();
                    CaapsLinqToDB.DBModels.MT564Message message = this.linqToDbHelper.GetEventDetailsByGolderRecordId((long)golderRecordId);
                    if (g != null)
                    {
                        if (conditionalFieldChange)
                        {
                            //if (g.GoldenRecordStatus != EventWorkFlowStatus.Complete && g.GoldenRecordStatus != EventWorkFlowStatus.PendingComplete)
                            //{
                            //    g.GoldenRecordStatus = EventWorkFlowStatus.PendingComplete;
                            //    g.EntryBy = userId;
                            //    g.IsAutoStp = false;
                            //    g.ReviewByDate = null;
                            //    g.EntryDtTime = DateTime.Now;
                            //    g.EntryDtTimeUtc = DateTime.UtcNow;
                            //    this.context.SaveChanges();
                            //    message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREC;
                            //    this.linqToDBContext.Update(message);
                            //    this.linqToDBContext.SaveChanges();
                            //    ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                            //    Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                            //}
                            if (conflicts.Any(x => x.ReviewStatus == (int)EventReviewStatus.InReview))
                            {
                                if (g.GoldenRecordStatus != EventWorkFlowStatus.PendingComplete)
                                {
                                    Logger.Log($"UpdateWorkFlowStatus EventWorkFlowStatus.PendingComplete", LogType.Info);

                                    g.GoldenRecordStatus = EventWorkFlowStatus.PendingComplete;
                                    g.EntryBy = userId;
                                    g.IsAutoStp = false;
                                    g.ReviewByDate = null;
                                    g.EntryDtTime = DateTime.Now;
                                    g.EntryDtTimeUtc = DateTime.UtcNow;
                                    this.context.SaveChanges();
                                    message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREC;
                                    this.linqToDBContext.Update(message);
                                    this.linqToDBContext.SaveChanges();
                                    ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                                    Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                                }
                            }
                            else
                            {
                                //Under CR#119 for add/clone option/movement the event workflow status should change to pending complete.
                                //And whereever we are making event direct complete their needs to add check of pending complete.
                                if (g.GoldenRecordStatus != EventWorkFlowStatus.Complete && g.GoldenRecordStatus != EventWorkFlowStatus.PendingComplete)
                                {
                                    Logger.Log($"UpdateWorkFlowStatus EventWorkFlowStatus.Complete", LogType.Info);
                                    g.GoldenRecordStatus = EventWorkFlowStatus.Complete;
                                    g.EntryBy = userId;
                                    g.IsAutoStp = false;
                                    g.ReviewByDate = null;
                                    g.EntryDtTime = DateTime.Now;
                                    g.EntryDtTimeUtc = DateTime.UtcNow;
                                    this.context.SaveChanges();
                                    message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREC;
                                    this.linqToDBContext.Update(message);
                                    this.linqToDBContext.SaveChanges();
                                    ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                                    Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                                }

                                if(fromAddOrCloneOptionOrMovementAction)
                                {
                                    g = this.context.GoldenRecordMsts.Where(gr => gr.GoldenRecordId == golderRecordId).FirstOrDefault();
                                    if(g.GoldenRecordStatus == EventWorkFlowStatus.Complete)
                                    {
                                        Logger.Log($"UpdateWorkFlowStatus EventWorkFlowStatus.PendingComplete", LogType.Info);
                                        g.GoldenRecordStatus = EventWorkFlowStatus.PendingComplete;
                                        g.EntryBy = userId;
                                        g.IsAutoStp = false;
                                        g.ReviewByDate = null;
                                        g.EntryDtTime = DateTime.Now;
                                        g.EntryDtTimeUtc = DateTime.UtcNow;
                                        this.context.SaveChanges();
                                        message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREC;
                                        this.linqToDBContext.Update(message);
                                        this.linqToDBContext.SaveChanges();
                                        ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                                        Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                                    }
                                }
                            }
                            //g.EntryBy = userId;
                            //g.IsAutoStp = false;
                            //g.ReviewByDate = null;
                            //g.EntryDtTime = DateTime.Now;
                            //g.EntryDtTimeUtc = DateTime.UtcNow;
                            //this.context.SaveChanges();
                            //message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREC;
                            //this.linqToDBContext.Update(message);
                            //this.linqToDBContext.SaveChanges();
                            //ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                            //Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                        }
                        else
                        {
                            Logger.Log($"UpdateWorkFlowStatus EventWorkFlowStatus.PendingComplete Conditional Field Change : {conditionalFieldChange}", LogType.Info);
                            g.GoldenRecordStatus = EventWorkFlowStatus.PendingComplete;
                            g.EntryBy = userId;
                            g.IsAutoStp = false;
                            g.ReviewByDate = null;
                            g.EntryDtTime = DateTime.Now;
                            g.EntryDtTimeUtc = DateTime.UtcNow;
                            this.context.SaveChanges();
                            message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREC;
                            this.linqToDBContext.Update(message);
                            this.linqToDBContext.SaveChanges();
                            ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                            Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                        }
                    }
                }
                else
                {
                    if (conditionalFieldChange)
                    {
                        GoldenRecordMst g = this.context.GoldenRecordMsts.Where(gr => gr.GoldenRecordId == golderRecordId).FirstOrDefault();
                        CaapsLinqToDB.DBModels.MT564Message message = this.linqToDbHelper.GetEventDetailsByGolderRecordId((long)golderRecordId);
                        if (g != null)
                        {
                            if (g.GoldenRecordStatus == EventWorkFlowStatus.Complete || g.GoldenRecordStatus == EventWorkFlowStatus.PendingComplete)
                            {
                                Logger.Log($"UpdateWorkFlowStatus EventWorkFlowStatus.Incomplete Conditional Field Change : {conditionalFieldChange}", LogType.Info);
                                g.GoldenRecordStatus = EventWorkFlowStatus.Incomplete;
                                g.EntryBy = userId;
                                g.IsAutoStp = false;
                                g.ReviewByDate = null;
                                g.EntryDtTime = DateTime.Now;
                                g.EntryDtTimeUtc = DateTime.UtcNow;
                                this.context.SaveChanges();
                                message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREC;
                                this.linqToDBContext.Update(message);
                                this.linqToDBContext.SaveChanges();
                                ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                                Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                            }
                        }
                    }


                }
            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);

            }
        }
        public EventReviewDateParameter UpdateEventReviewDate(EventReviewDateParameter eventDetail, int userId)
        {
            try
            {
                GoldenRecordMst goldenRecord = this.context.GoldenRecordMsts.Where(a => a.GoldenRecordId == eventDetail.GoldenRecordID).FirstOrDefault();
                CaapsLinqToDB.DBModels.MT564Message message = this.linqToDbHelper.GetEventDetailsByGolderRecordId((long)eventDetail.GoldenRecordID);
                if (goldenRecord != null)
                {
                    goldenRecord.EntryBy = userId;
                    goldenRecord.EntryDtTime = DateTime.Now;
                    goldenRecord.EntryDtTimeUtc = DateTime.UtcNow;
                    goldenRecord.ReviewByDate = eventDetail.ReviewByDate;
                    int statusUpdate = 0;
                    if (goldenRecord.GoldenRecordStatus != EventWorkFlowStatus.Complete)
                    {
                        statusUpdate = 1;
                        Logger.Log($"UpdateEventReviewDate EventWorkFlowStatus.Conditional", LogType.Info);
                        goldenRecord.GoldenRecordStatus = EventWorkFlowStatus.Conditional;
                        goldenRecord.IsAutoStp = false;
                        message.MessageData.GeneralInformation.StatusCode = EventProcessingStatus.PREC;
                    }
                    this.context.SaveChanges();
                    this.linqToDBContext.Update(message);
                    this.linqToDBContext.SaveChanges();
                    eventDetail.IsSuccess = true;
                    eventDetail.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Updated);
                    eventDetail.MessageId = (int)ResponseCodeMessage.Updated;
                    if (statusUpdate == 1)
                    {
                        ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, goldenRecord);
                        Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                    }
                    SaveInActiveDate(eventDetail.GoldenRecordID);
                    sendEventNotification(
                    $"Review Date Updated",
                    "EVENT_APPROVAL",
                    new
                    {
                        GoldenId = eventDetail.GoldenRecordID
                    });
                }
                else
                {
                    eventDetail.IsSuccess = false;
                    eventDetail.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NotFound);
                    eventDetail.MessageId = (int)ResponseCodeMessage.NotFound;
                }
            }
            catch (Exception ex)
            {
                eventDetail.IsSuccess = false;
                eventDetail.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InvalidData);
                eventDetail.MessageId = (int)ResponseCodeMessage.InvalidData;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.EventReviewDetail = JsonConvert.SerializeObject(eventDetail);
                logs.userId = userId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return eventDetail;
        }


        public EventInActiveDateParameter UpdateEventInActiveDate(EventInActiveDateParameter eventDetail, int userId)
        {
            try
            {
                GoldenRecordMst goldenRecord = this.context.GoldenRecordMsts.Where(a => a.GoldenRecordId == eventDetail.GoldenRecordID).FirstOrDefault();
                if (goldenRecord != null)
                {
                    goldenRecord.EntryBy = userId;
                    goldenRecord.EntryDtTime = DateTime.Now;
                    goldenRecord.EntryDtTimeUtc = DateTime.UtcNow;
                    if (eventDetail.InActiveDate.Date >= DateTime.UtcNow.Date)
                    {
                        goldenRecord.InactiveDate = eventDetail.InActiveDate;
                        goldenRecord.IsActive = 1;
                        eventDetail.IsSuccess = true;
                        eventDetail.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Updated);
                        eventDetail.MessageId = (int)ResponseCodeMessage.Updated;
                        this.context.SaveChanges();
                    }
                    else
                    {
                        eventDetail.IsSuccess = false;
                        eventDetail.Message = "inactive date can not be less than today.";
                        eventDetail.MessageId = (int)ResponseCodeMessage.NotFound;
                    }
                }
                else
                {
                    eventDetail.IsSuccess = false;
                    eventDetail.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NotFound);
                    eventDetail.MessageId = (int)ResponseCodeMessage.NotFound;
                }
            }
            catch (Exception ex)
            {
                eventDetail.IsSuccess = false;
                eventDetail.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InvalidData);
                eventDetail.MessageId = (int)ResponseCodeMessage.InvalidData;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.EventReviewDetail = JsonConvert.SerializeObject(eventDetail);
                logs.userId = userId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return eventDetail;
        }

        public EventReceivedResponse GetEventReceivedResponse(int goldenId)
        {
            EventReceivedResponse eventReceivedResponse = new EventReceivedResponse();
            try
            {
                var receivedMessages = (
                    from grcem in this.context.GoldenRecordSourceEventMappings
                    join rced in this.context.ReceivedCaEventDtls on Convert.ToInt32(grcem.ReceivedId) equals rced.ReceivedCaEventDtlId
                    where (grcem.GoldenRecordId == goldenId) && (grcem.IsActive == 1)
                    select new EventReceivedDetail
                    {
                        GoldenRecordSourceEventMappingId = grcem.GoldenRecordSourceEventMappingId,
                        GoldenRecordId = grcem.GoldenRecordId,
                        SourceName = (rced.FileImportMstId == -2) ? this.context.UserMsts.Where(x => x.UserId == Convert.ToInt32(grcem.SourceName)).FirstOrDefault().FullName : grcem.SourceName,
                        SourceIdentifier = null,
                        CORPId = grcem.CorpId,
                        ReceivedId = Convert.ToInt32(grcem.ReceivedId),
                        CAEventForDate = rced.CaEventForDate,
                        ExtractedMessage = rced.ExtractedMessage,
                        BloomberId = rced.BloombergId,
                        Cusip = rced.Cusip,
                        ISIN = rced.Isin,
                        SEDOL = rced.Sedol,
                        IsProcessed = rced.IsProcessed,
                        Message = (rced.FileImportMstId == -2) ? "Manual" : (grcem.MessageType == null ? "MT564" : (grcem.MessageType == string.Empty ? "MT564" : grcem.MessageType)),
                        EntryDateTimeUtc = grcem.EntryDtTimeUtc,
                        IsManual = (rced.FileImportMstId == -2)
                    }).ToList();

                receivedMessages.AddRange(
                    (from grcem in this.context.GoldenRecordSourceEventMappingAudits
                     join rced in this.context.ReceivedCaEventDtls on Convert.ToInt32(grcem.ReceivedId) equals rced.ReceivedCaEventDtlId
                     where (grcem.GoldenRecordId == goldenId) && (grcem.IsActive == 1)
                     select new EventReceivedDetail
                     {
                         GoldenRecordSourceEventMappingId = (long)grcem.GoldenRecordSourceEventMappingId,
                         GoldenRecordId = (long)grcem.GoldenRecordId,
                         SourceName = (rced.FileImportMstId == -2) ? this.context.UserMsts.Where(x => x.UserId == Convert.ToInt32(grcem.SourceName)).FirstOrDefault().FullName : grcem.SourceName,
                         SourceIdentifier = null,
                         CORPId = grcem.CorpId,
                         ReceivedId = Convert.ToInt32(grcem.ReceivedId),
                         CAEventForDate = rced.CaEventForDate,
                         ExtractedMessage = rced.ExtractedMessage,
                         BloomberId = rced.BloombergId,
                         Cusip = rced.Cusip,
                         ISIN = rced.Isin,
                         SEDOL = rced.Sedol,
                         IsProcessed = rced.IsProcessed,
                         Message = (rced.FileImportMstId == -2) ? "Manual" : (grcem.MessageType == null ? "MT564" : (grcem.MessageType == string.Empty ? "MT564" : grcem.MessageType)),
                         EntryDateTimeUtc = (DateTime)grcem.EntryDtTimeUtc,
                         IsManual = (rced.FileImportMstId == -2)
                     }).ToList()
                    );

                receivedMessages.AddRange(
                    (from grcem in this.context.GoldenRecordSourceEventMt568Mapping
                     join rced in this.context.ReceivedCaEventDtls on Convert.ToInt32(grcem.ReceivedId) equals rced.ReceivedCaEventDtlId
                     where (grcem.GoldenRecordId == goldenId) && (grcem.IsActive == 1)
                     select new EventReceivedDetail
                     {
                         GoldenRecordSourceEventMappingId = grcem.GoldenRecordSourceEventMt568MappingId,
                         GoldenRecordId = grcem.GoldenRecordId,
                         SourceName = grcem.SourceName,
                         SourceIdentifier = null,
                         CORPId = grcem.CorpId,
                         ReceivedId = Convert.ToInt32(grcem.ReceivedId),
                         CAEventForDate = rced.CaEventForDate,
                         ExtractedMessage = rced.ExtractedMessage,
                         BloomberId = rced.BloombergId,
                         Cusip = rced.Cusip,
                         ISIN = rced.Isin,
                         SEDOL = rced.Sedol,
                         IsProcessed = rced.IsProcessed,
                         Message = "MT568",
                         EntryDateTimeUtc = grcem.EntryDtTimeUtc,
                         IsManual = (rced.FileImportMstId == -2)
                     }).ToList()
                    );

                receivedMessages.AddRange(
                    (from grcem in this.context.GoldenRecordSourceEventMt568MappingAudit
                     join rced in this.context.ReceivedCaEventDtls on Convert.ToInt32(grcem.ReceivedId) equals rced.ReceivedCaEventDtlId
                     where (grcem.GoldenRecordId == goldenId) && (grcem.IsActive == 1)
                     select new EventReceivedDetail
                     {
                         GoldenRecordSourceEventMappingId = (long)grcem.GoldenRecordSourceEventMt568MappingId,
                         GoldenRecordId = (long)grcem.GoldenRecordId,
                         SourceName = grcem.SourceName,
                         SourceIdentifier = null,
                         CORPId = grcem.CorpId,
                         ReceivedId = Convert.ToInt32(grcem.ReceivedId),
                         CAEventForDate = rced.CaEventForDate,
                         ExtractedMessage = rced.ExtractedMessage,
                         BloomberId = rced.BloombergId,
                         Cusip = rced.Cusip,
                         ISIN = rced.Isin,
                         SEDOL = rced.Sedol,
                         IsProcessed = rced.IsProcessed,
                         Message = "MT568",
                         EntryDateTimeUtc = (DateTime)grcem.EntryDtTimeUtc,
                         IsManual = (rced.FileImportMstId == -2)
                     }).ToList()
                    );

                eventReceivedResponse.ReceivedDetails = receivedMessages.OrderByDescending(x => x.EntryDateTimeUtc).ToList();
                eventReceivedResponse.IsSuccess = true;
                eventReceivedResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                eventReceivedResponse.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                eventReceivedResponse.IsSuccess = false;
                eventReceivedResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                eventReceivedResponse.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = goldenId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return eventReceivedResponse;
        }

        public OptionsLinkResponse GetLinkOptionsByGoldenId(int goldenId)
        {
            OptionsLinkResponse optionsLinkResponse = new OptionsLinkResponse();
            try
            {

                List<OptionLinkDbResult> optionLinksDb = (from o in this.context.CaOptionLinks
                                                          join a in this.context.GoldenRecordSourceEventMappings on o.SourceEventId equals a.SemeRef into grOptionLink
                                                          from oLink in grOptionLink.DefaultIfEmpty()
                                                          where (o.GoldenRecordId == goldenId) && (o.IsActive == 1)
                                                          select new OptionLinkDbResult
                                                          {
                                                              CaOptionLinkId = o.CaOptionLinkId,
                                                              GoldenRecordId = o.GoldenRecordId,
                                                              ClientLinkStatus = o.ClientLinkStatus,
                                                              ClientOptionNumber = o.ClientOptionNumber,
                                                              ClientOptionStatus = o.ClientOptionStatus,
                                                              SourceName = o.SourceName,
                                                              SourceBic = o.SourceBic,
                                                              SourceEventId = o.SourceEventId,
                                                              SourceOptionNumber = o.SourceOptionNumber,
                                                              SourceOptionStatus = o.SourceOptionStatus,
                                                              IsActive = o.IsActive,
                                                              EntryBy = o.EntryBy,
                                                              EntryDtTime = o.EntryDtTime,
                                                              EntryDtTimeUtc = o.EntryDtTimeUtc,
                                                              SourceLinkStatus = o.SourceLinkStatus,
                                                              ReceivedId = oLink.ReceivedId,
                                                              CorpId = oLink.CorpId,
                                                              MessageType = oLink.MessageType,
                                                              SemeRef = oLink.SemeRef,
                                                              SourceEventMappingId = oLink.GoldenRecordSourceEventMappingId
                                                          }).ToList();

                var optionLinkDbAudit = (from o in this.context.CaOptionLinks
                                         join a in this.context.GoldenRecordSourceEventMappingAudits on o.SourceEventId equals a.SemeRef into grOptionLink
                                         from oLink in grOptionLink.DefaultIfEmpty()
                                         where (o.GoldenRecordId == goldenId) && (o.IsActive == 1)
                                         select new OptionLinkDbResult
                                         {
                                             CaOptionLinkId = o.CaOptionLinkId,
                                             GoldenRecordId = o.GoldenRecordId,
                                             ClientLinkStatus = o.ClientLinkStatus,
                                             ClientOptionNumber = o.ClientOptionNumber,
                                             ClientOptionStatus = o.ClientOptionStatus,
                                             SourceName = o.SourceName,
                                             SourceBic = o.SourceBic,
                                             SourceEventId = o.SourceEventId,
                                             SourceOptionNumber = o.SourceOptionNumber,
                                             SourceOptionStatus = o.SourceOptionStatus,
                                             IsActive = o.IsActive,
                                             EntryBy = o.EntryBy,
                                             EntryDtTime = o.EntryDtTime,
                                             EntryDtTimeUtc = o.EntryDtTimeUtc,
                                             SourceLinkStatus = o.SourceLinkStatus,
                                             ReceivedId = oLink.ReceivedId,
                                             CorpId = oLink.CorpId,
                                             MessageType = oLink.MessageType,
                                             SemeRef = oLink.SemeRef,
                                             SourceEventMappingId = oLink.GoldenRecordSourceEventMappingId
                                         }).ToList();

                optionLinksDb.AddRange(optionLinkDbAudit.Where(x => x.ReceivedId != null));

                optionLinksDb = optionLinksDb.GroupBy(x => new { x.ClientOptionNumber, x.SourceOptionNumber, x.SourceName }, (key, g) => g.OrderBy(e => e.SourceEventMappingId).First()).ToList();

                //List<CaOptionLink> optionLinksDb = this.context.CaOptionLinks.Where(a => a.GoldenRecordId == goldenId).ToList();
                if (optionLinksDb.Count > 0)
                {
                    //MT564Message mt564 = this.swiftContext.GetSwiftMessageByIdWithCriteria(a => a.GoldenRecordID == goldenId, false);
                    CaapsLinqToDB.DBModels.MT564Message mt564New = this.linqToDbHelper.GetEventDetailsByGolderRecordId(goldenId);
                    List<CAOptionsLink> optionsLinks = new List<CAOptionsLink>();
                    foreach (var optionLink in optionLinksDb)
                    {
                        try
                        {
                            CAOptionsLink caOptions = new CAOptionsLink();
                            caOptions.CaOptionLinkId = optionLink.CaOptionLinkId;
                            caOptions.GoldenRecordId = optionLink.GoldenRecordId;
                            caOptions.ClientLinkStatus = optionLink.ClientLinkStatus;
                            caOptions.ClientOptionNumber = optionLink.ClientOptionNumber;
                            caOptions.ClientOptionStatus = optionLink.ClientOptionStatus;
                            caOptions.SourceName = optionLink.SourceName;
                            caOptions.SourceBic = optionLink.SourceBic;
                            caOptions.SourceEventId = optionLink.SourceEventId;
                            caOptions.SourceOptionNumber = optionLink.SourceOptionNumber;
                            caOptions.SourceOptionStatus = optionLink.SourceOptionStatus;
                            caOptions.IsActive = optionLink.IsActive;
                            caOptions.EntryBy = optionLink.EntryBy;
                            caOptions.EntryDtTime = optionLink.EntryDtTime;
                            caOptions.EntryDtTimeUtc = optionLink.EntryDtTimeUtc;
                            caOptions.SourceLinkStatus = optionLink.SourceLinkStatus;
                            if (mt564New.MessageData.CorporateActionOptions.Count > 0 && optionLink.ClientOptionNumber != String.Empty)
                            {
                                CaapsLinqToDB.DBModels.MCorporateActionOption mCorporateActionOption = mt564New.MessageData.CorporateActionOptions.ToList().Find(a => a.CaoptionNumber.NumberId == optionLink.ClientOptionNumber);
                                if (mCorporateActionOption != null)
                                {
                                    CaapsLinqToDB.DBModels.MIndicator indc = mCorporateActionOption.Indicator.Where(x => x.Qualifier == "CAOP").FirstOrDefault();
                                    CaapsLinqToDB.DBModels.MFlag mFlag = mCorporateActionOption.Flag.FirstOrDefault();
                                    caOptions.ClientOptionType = indc.Indicator;
                                    if (mFlag.Qualifier == "DFLT")
                                    {
                                        caOptions.ClientDefault = mFlag.Flag;
                                    }
                                }
                            }

                            if (optionLink.ReceivedId != String.Empty && optionLink.ReceivedId != null)
                            {
                                ReceivedCaEventDtl receivedCaEventDtl = this.context.ReceivedCaEventDtls.Where(a => a.ReceivedCaEventDtlId == int.Parse(optionLink.ReceivedId)).FirstOrDefault();
                                if (receivedCaEventDtl != null && receivedCaEventDtl.NormalizedMessage != null)
                                {
                                    CaapsLinqToDB.DBModels.MT564Message sourceMT564 = JsonConvert.DeserializeObject<CaapsLinqToDB.DBModels.MT564Message>(receivedCaEventDtl.NormalizedMessage);

                                    if (sourceMT564 != null && sourceMT564.MessageData.CorporateActionOptions.Count > 0)
                                    {
                                        CaapsLinqToDB.DBModels.MCorporateActionOption mCorporateActionOption = sourceMT564.MessageData.CorporateActionOptions.ToList().Find(a => a.CaoptionNumber.NumberId == optionLink.SourceOptionNumber);
                                        if (mCorporateActionOption != null)
                                        {
                                            CaapsLinqToDB.DBModels.MIndicator indc = mCorporateActionOption.Indicator.Where(x => x.Qualifier == "CAOP").FirstOrDefault();
                                            CaapsLinqToDB.DBModels.MFlag mFlag = mCorporateActionOption.Flag.FirstOrDefault();
                                            caOptions.SourceOptionType = indc.Indicator;
                                            if (mFlag.Qualifier == "DFLT")
                                            {
                                                caOptions.SourceDefault = mFlag.Flag;
                                            }
                                        }
                                    }
                                }
                            }
                            optionsLinks.Add(caOptions);
                        }
                        catch (Exception ex)
                        {
                            dynamic logs = new ExpandoObject();
                            logs.StackTrace = ex.StackTrace;
                            logs.goldenRecordId = goldenId;
                            Logger.LogException(ex, LogType.Error, logs);
                        }
                    }
                    List<CAOptionsLink> sourceOptionsLinks = optionsLinks.Where(a => a.SourceName != null && a.SourceName != String.Empty).ToList();
                    Dictionary<string, List<CAOptionsLink>> sourceOptions = sourceOptionsLinks.OrderByDescending(a => a.EntryDtTimeUtc).GroupBy(a => a.SourceName).ToDictionary(a => a.Key, a => a.DistinctBy(x => x.SourceOptionNumber).ToList());
                    optionsLinkResponse.SourceOptions = sourceOptions;
                    optionsLinkResponse.LinkedOptions = optionsLinks.Where(a => a.ClientOptionNumber != "" && a.SourceOptionNumber != "").ToList();
                    optionsLinkResponse.ClientOptions = optionsLinks.Where(a => a.ClientOptionNumber != "" && a.SourceOptionNumber != "").OrderBy(a => a.ClientOptionNumber).ThenBy(a => a.ClientLinkStatus).DistinctBy(a => a.ClientOptionNumber).ToList();
                    if (optionsLinkResponse.ClientOptions.Count != optionsLinks.Where(a => a.ClientOptionNumber != "").DistinctBy(a => a.ClientOptionNumber).ToList().Count)
                    {
                        var tempOptionLinks = optionsLinks;
                        foreach (var tempOptionLink in tempOptionLinks)
                        {
                            if (!optionsLinkResponse.ClientOptions.Any(x => x.ClientOptionNumber == tempOptionLink.ClientOptionNumber))
                            {
                                optionsLinkResponse.ClientOptions.Add(tempOptionLink);
                            }
                        }
                    }
                    optionsLinkResponse.ClientOptions = optionsLinkResponse.ClientOptions.OrderBy(x => x.ClientOptionNumber).ToList();
                }
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = goldenId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return optionsLinkResponse;
        }
        public OptionsLinkRequest SaveLinkOptions(OptionsLinkRequest optionsLink, int UserId)
        {
            OptionsLinkResponse optionsLinkResponse = new OptionsLinkResponse();
            try
            {
                List<CaOptionLink> optionLinksDb = this.context.CaOptionLinks.Where(a => a.GoldenRecordId == optionsLink.GoldenRecordId).ToList();
                if (optionLinksDb.Count > 0)
                {
                    foreach (var option in optionsLink.LinkOptions)
                    {
                        CaOptionLink caOptionLink = optionLinksDb.Find(a => a.ClientOptionNumber == option.ClientOptionNumber && a.SourceOptionNumber == option.SourceOptionNumber && a.SourceName == option.SourceName);
                        if (caOptionLink != null)
                        {
                            caOptionLink.SourceLinkStatus = option.SourceLinkStatus;
                            caOptionLink.ClientLinkStatus = option.ClientLinkStatus;
                            caOptionLink.EntryBy = UserId;
                            caOptionLink.EntryDtTime = DateTime.Now;
                            caOptionLink.EntryDtTimeUtc = DateTime.UtcNow;

                            CaOptionException sourceException = this.context.CaOptionExceptions.Where(x => x.GoldenRecordId == optionsLink.GoldenRecordId
                            && x.ExceptionType == "Unlinked Source Option" && x.SourceName == caOptionLink.SourceName && x.OptionNumber == caOptionLink.SourceOptionNumber
                            ).FirstOrDefault();

                            CaOptionException clientException = this.context.CaOptionExceptions.Where(x => x.GoldenRecordId == optionsLink.GoldenRecordId
                            && x.ExceptionType == "Unlinked Client Option" && x.SourceName == caOptionLink.SourceName && x.OptionNumber == caOptionLink.ClientOptionNumber
                            ).FirstOrDefault();

                            if (sourceException != null)
                            {
                                if (caOptionLink.SourceLinkStatus == "Unlinked")
                                {
                                    sourceException.ExceptionStatus = "Open";
                                }
                                else if (caOptionLink.SourceLinkStatus == "Linked")
                                {
                                    sourceException.ExceptionStatus = "User Resolved";
                                }

                                this.context.CaOptionExceptions.Update(sourceException);
                            }
                            else
                            {
                                sourceException = new CaOptionException();
                                if (caOptionLink.SourceLinkStatus == "Unlinked")
                                {
                                    sourceException.GoldenRecordId = optionsLink.GoldenRecordId;
                                    sourceException.ExceptionType = "Unlinked Source Option";
                                    sourceException.ExceptionMessage = "Unlinked manually by User";
                                    sourceException.SourceName = option.SourceName;
                                    sourceException.SourceBic = option.SourceBic;
                                    sourceException.SourceEventId = option.SourceEventId;
                                    sourceException.OptionNumber = option.SourceOptionNumber;
                                    sourceException.IsActive = 1;
                                    sourceException.EntryBy = UserId;
                                    sourceException.EntryDtTime = DateTime.Now;
                                    sourceException.EntryDtTimeUtc = DateTime.UtcNow;
                                    sourceException.MovementId = "";
                                    if (caOptionLink.SourceLinkStatus == "Unlinked")
                                    {
                                        sourceException.ExceptionStatus = "Open";
                                    }
                                    else if (caOptionLink.SourceLinkStatus == "Linked")
                                    {
                                        sourceException.ExceptionStatus = "User Resolved";
                                    }

                                    this.context.CaOptionExceptions.Add(sourceException);
                                }

                            }

                            if (clientException != null)
                            {
                                if (caOptionLink.ClientLinkStatus == "Unlinked")
                                {
                                    clientException.ExceptionStatus = "Open";
                                }
                                else if (caOptionLink.ClientLinkStatus == "Linked")
                                {
                                    clientException.ExceptionStatus = "User Resolved";
                                }

                                this.context.CaOptionExceptions.Update(clientException);
                            }
                            else
                            {
                                clientException = new CaOptionException();
                                if (caOptionLink.ClientLinkStatus == "Unlinked")
                                {
                                    clientException.GoldenRecordId = optionsLink.GoldenRecordId;
                                    clientException.ExceptionType = "Unlinked Client Option";
                                    clientException.ExceptionMessage = "Unlinked manually by User";
                                    clientException.SourceName = option.SourceName;
                                    clientException.SourceBic = option.SourceBic;
                                    clientException.SourceEventId = option.SourceEventId;
                                    clientException.OptionNumber = option.ClientOptionNumber;
                                    clientException.IsActive = 1;
                                    clientException.EntryBy = UserId;
                                    clientException.EntryDtTime = DateTime.Now;
                                    clientException.EntryDtTimeUtc = DateTime.UtcNow;
                                    clientException.MovementId = "";
                                    if (caOptionLink.ClientLinkStatus == "Unlinked")
                                    {
                                        clientException.ExceptionStatus = "Open";
                                    }
                                    else if (caOptionLink.ClientLinkStatus == "Linked")
                                    {
                                        clientException.ExceptionStatus = "User Resolved";
                                    }

                                    this.context.CaOptionExceptions.Add(clientException);
                                }
                            }
                        }
                        else
                        {
                            CaOptionLink newOptionLink = new CaOptionLink();
                            newOptionLink.GoldenRecordId = optionsLink.GoldenRecordId;
                            newOptionLink.ClientLinkStatus = "Linked";
                            newOptionLink.ClientOptionNumber = option.ClientOptionNumber;
                            newOptionLink.SourceName = option.SourceName;
                            newOptionLink.SourceBic = option.SourceBic;
                            newOptionLink.SourceEventId = option.SourceEventId;
                            newOptionLink.SourceOptionNumber = option.SourceOptionNumber;
                            newOptionLink.IsActive = 1;
                            newOptionLink.EntryBy = UserId;
                            newOptionLink.SourceLinkStatus = option.SourceLinkStatus;
                            newOptionLink.EntryDtTime = DateTime.Now;
                            newOptionLink.EntryDtTimeUtc = DateTime.UtcNow;
                            newOptionLink.ClientOptionStatus = "";
                            newOptionLink.SourceOptionStatus = "";
                            this.context.CaOptionLinks.Add(newOptionLink);

                            CaOptionException sourceException = this.context.CaOptionExceptions.Where(x => x.GoldenRecordId == optionsLink.GoldenRecordId
                            && x.ExceptionType == "Unlinked Source Option" && x.SourceName == newOptionLink.SourceName && x.OptionNumber == newOptionLink.SourceOptionNumber
                            ).FirstOrDefault();

                            CaOptionException clientException = this.context.CaOptionExceptions.Where(x => x.GoldenRecordId == optionsLink.GoldenRecordId
                            && x.ExceptionType == "Unlinked Client Option" && x.SourceName == newOptionLink.SourceName && x.OptionNumber == newOptionLink.ClientOptionNumber
                            ).FirstOrDefault();

                            if (sourceException != null)
                            {
                                sourceException.ExceptionStatus = "User Resolved";
                                this.context.CaOptionExceptions.Update(sourceException);
                            }

                            if (clientException != null)
                            {
                                clientException.ExceptionStatus = "User Resolved";
                                this.context.CaOptionExceptions.Update(clientException);
                            }

                            //caOptionLink = optionLinksDb.Find(a => a.ClientOptionNumber == option.ClientOptionNumber && a.SourceName == option.SourceName && a.SourceOptionNumber == "");
                            //if (caOptionLink != null)
                            //{
                            //    caOptionLink.SourceOptionNumber = caOptionLink.SourceOptionNumber;
                            //    caOptionLink.SourceLinkStatus = option.SourceLinkStatus;
                            //    caOptionLink.ClientLinkStatus = option.ClientLinkStatus;
                            //    caOptionLink.EntryBy = UserId;
                            //    caOptionLink.EntryDtTime = DateTime.Now;
                            //    caOptionLink.EntryDtTimeUtc = DateTime.UtcNow;
                            //}
                            //else
                            //{
                            //    caOptionLink = optionLinksDb.Find(a => a.SourceOptionNumber == option.SourceOptionNumber && a.SourceName == option.SourceName);
                            //    caOptionLink.ClientOptionNumber = caOptionLink.SourceOptionNumber;
                            //    caOptionLink.SourceLinkStatus = option.SourceLinkStatus;
                            //    caOptionLink.ClientLinkStatus = option.ClientLinkStatus;
                            //    caOptionLink.EntryBy = UserId;
                            //    caOptionLink.EntryDtTime = DateTime.Now;
                            //    caOptionLink.EntryDtTimeUtc = DateTime.UtcNow;
                            //}
                        }
                        this.context.SaveChanges();
                    }
                }
                optionsLink.IsSuccess = true;
                optionsLink.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                optionsLink.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.optionLink = JsonConvert.SerializeObject(optionsLink);
                Logger.LogException(ex, LogType.Error, logs);
                optionsLink.IsSuccess = false;
                optionsLink.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                optionsLink.MessageId = (int)ResponseCodeMessage.InternalServerError;
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            sendEventNotification(
                     $"Option Linking Performed",
                     "LINK_OPTION",
                      new
                      {
                          GoldenId = optionsLink.GoldenRecordId
                      });

            //sendEventNotification(
            //        $"Event approval perform",
            //        "EVENT_APPROVAL",
            //        new
            //        {
            //            GoldenId = optionsLink.GoldenRecordId
            //        });

            return optionsLink;
        }

        public void SaveCaOptions()
        {
            try
            {
                MT564Message mt564 = this.swiftContext.GetSwiftMessageByIdWithCriteria(a => a.GoldenRecordID == 10329, true);
                DisplayData displayData = this.displayDataHelper.GetDisplayData(a => a.GoldenRecordID == 10329, false);
                DisplayToMt564 displayToMt564 = new DisplayToMt564();
                mt564 = displayToMt564.TransformDisplayToMt564(mt564, displayData);
                this.swiftContext.SaveChanges();
            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
        }
        public List<CaOptionException> GetEventExceptions(int goldenRecordId)
        {
            List<CaOptionException> eventExceptions = new List<CaOptionException>();
            try
            {
                eventExceptions = this.context.CaOptionExceptions.Where(x => x.GoldenRecordId == goldenRecordId).ToList();
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = goldenRecordId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return eventExceptions;
        }

        public List<CAOptions> GetSourceOptionsByGoldenId(int goldenId, string source)
        {
            List<CAOptions> cAOptions = new List<CAOptions>();
            try
            {
                GoldenRecordSourceEventMapping goldenRecordSourceEventMapping =
                    this.context.GoldenRecordSourceEventMappings.Where(a => a.GoldenRecordId == goldenId && a.SourceName.ToUpper() == source.ToUpper()).OrderByDescending(x => x.EntryDtTimeUtc).FirstOrDefault();
                ReceivedCaEventDtl receivedCaEventDtl = this.context.ReceivedCaEventDtls.Where(a => a.ReceivedCaEventDtlId == int.Parse(goldenRecordSourceEventMapping.ReceivedId)).FirstOrDefault();
                if ((receivedCaEventDtl?.NormalizedMessage ?? null) != null)
                {
                    CaapsLinqToDB.DBModels.MT564Message sourceMT564 = JsonConvert.DeserializeObject<CaapsLinqToDB.DBModels.MT564Message>(receivedCaEventDtl.NormalizedMessage);
                    DisplayData displayData = this.displayDataHelper.ToDisplayData(sourceMT564);
                    cAOptions = displayData.Options;
                    List<CaOptionLink> optionLinksDb = this.context.CaOptionLinks.Where(a => a.GoldenRecordId == goldenId).ToList();
                    cAOptions.ForEach(option =>
                    {
                        try
                        {
                            if (optionLinksDb != null)
                            {
                                var linkDetail = optionLinksDb.Where(x => x.SourceOptionNumber == option.CaOptOptionNumber && x.SourceName.ToUpper() == source.ToUpper() && !String.IsNullOrEmpty(x.SourceLinkStatus));
                                if (linkDetail != null)
                                {
                                    option.LinkStatus = linkDetail.Any(x => x.ClientLinkStatus == "Linked") ? "Linked" : "Unlinked";
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            dynamic logs = new ExpandoObject();
                            logs.StackTrace = ex.StackTrace;
                            logs.goldenRecordId = goldenId;
                            logs.source = source;
                            Logger.LogException(ex, LogType.Error, logs);
                        }

                    });

                }
            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return cAOptions;
        }

        public AllSourceResponse GetAllSourceByGoldenId(long goldenId)
        {
            AllSourceResponse allSourceResponse = new AllSourceResponse();
            try
            {
                List<CaOptionLink> optionLinksDb = this.context.CaOptionLinks.Where(a => a.GoldenRecordId == goldenId).DistinctBy(a => a.SourceName).ToList();
                allSourceResponse.Sources = new List<EventSource>();
                foreach (var source in optionLinksDb)
                {
                    if (source.SourceOptionNumber != null && source.SourceOptionNumber != String.Empty)
                    {
                        EventSource eventSource = new EventSource();
                        eventSource.EventSourceId = source.CaOptionLinkId;
                        eventSource.EventSourceName = source.SourceName;
                        allSourceResponse.Sources.Add(eventSource);
                    }
                }
                if (allSourceResponse.Sources.Count == 0)
                {
                    List<GoldenRecordSourceEventMapping> sourcesData = this.context.GoldenRecordSourceEventMappings.Where(x => x.GoldenRecordId == goldenId).DistinctBy(a => a.SourceName).ToList();
                    foreach (var source in sourcesData)
                    {
                        EventSource eventSource = new EventSource();
                        eventSource.EventSourceId = source.GoldenRecordSourceEventMappingId;
                        eventSource.EventSourceName = source.SourceName;
                        allSourceResponse.Sources.Add(eventSource);
                    }
                }
                allSourceResponse.IsSuccess = true;
                allSourceResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                allSourceResponse.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                allSourceResponse.IsSuccess = false;
                allSourceResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                allSourceResponse.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = goldenId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return allSourceResponse;
        }

        public ResponseParent UpdateMT565StatusPosition(int goldenRecordId, int CaEventElectionOptionsDtlId, string Status, string Role, string ExternalComment, int userId)
        {
            ResponseParent res = new ResponseParent();
            try
            {
                if (Role != UserRoleConsts.SUPERVISOR && Role != UserRoleConsts.SYSTEM_ADMIN)
                {
                    res.IsSuccess = false;
                    res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.NoPermission);
                    res.MessageId = (int)ResponseCodeMessage.NoPermission;
                }
                else
                {
                    CaEventElectionOptionsDtl eventDtl = this.context.CaEventElectionOptionsDtls.Where(c => c.GoldenRecordId == goldenRecordId &&
                                                                                                             c.CaEventElectionOptionsDtlId == CaEventElectionOptionsDtlId).FirstOrDefault();

                    var isDefault = this.context.CaEventElectionMappings.Where(x => x.CaEventElectionMappingId == eventDtl.CaEventElectionMappingId)
                        .Select(x => new
                        {
                            x.IsDefault,
                            x.Mt564SemeRef
                        }).FirstOrDefault();

                    if (eventDtl != null)
                    {
                        eventDtl.OptionStatus = Status;
                        eventDtl.ExternalComment = ExternalComment;
                        eventDtl.EntryBy = userId;
                        eventDtl.EntryDtTime = DateTime.Now;
                        eventDtl.EntryDtTimeUtc = DateTime.UtcNow;
                        this.context.SaveChanges();
                        MT565MsgFromSwiftProcessor obj = new MT565MsgFromSwiftProcessor();
                        if (isDefault.IsDefault == 1)
                        {
                            obj.CorpRef = Convert.ToString(goldenRecordId);
                            obj.mt565Ref = eventDtl.CaEventElectionOptionsDtlId.ToString();
                            obj.mt564Ref = isDefault.Mt564SemeRef;
                            obj.type = eventDtl.OptionStatus;
                            obj.mt565Json = null;
                            obj.isDefault = true;
                        }
                        else
                        {
                            obj.CorpRef = Convert.ToString(goldenRecordId);
                            obj.mt565Ref = eventDtl.Mt565SemeRef;
                            obj.mt564Ref = "";
                            obj.type = eventDtl.OptionStatus;
                            obj.mt565Json = null;
                            obj.isDefault = false;
                        }


                        if (solaceSettings.SendToTopic)
                        {
                            this.solaceMessageListener.SendToTopic(solaceSettings.MT565OutBoundTopicName, JsonConvert.SerializeObject(obj));
                        }
                        else
                        {
                            this.solaceMessageListener.SendToQueue(solaceSettings.MT565OutBoundQueueName, JsonConvert.SerializeObject(obj));
                        }
                        //this.solaceMessageListener.SendMessage(solaceSettings.MT565OutBoundQueueName, JsonConvert.SerializeObject(obj));
                        //this.solaceMessageListener.SendToQueue("caaps_dev_outboundqueue_mt567", JsonConvert.SerializeObject(obj));

                        res.IsSuccess = true;
                        res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                        res.MessageId = (int)ResponseCodeMessage.Successful;
                    }
                }

            }
            catch (Exception ex)
            {
                res.IsSuccess = false;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                res.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = goldenRecordId;
                logs.CaEventElectionOptionsDtlId = CaEventElectionOptionsDtlId;
                logs.Status = Status;
                logs.Role = Role;
                logs.UserId = userId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return res;
        }

        public ResponseParent SendSolaceMessage(string queueName, MT564Message updatedMessage, GoldenRecordMst golderRecordDetails)
        {
            ResponseParent res = new ResponseParent();

            try
            {
                SolacePositionCheckModel spCM = new SolacePositionCheckModel();
                spCM.Type = "event";
                spCM.GoldenRecordId = golderRecordDetails.GoldenRecordId;
                spCM.EventMsg = JsonConvert.SerializeObject(updatedMessage);
                spCM.PositionMsg = null;
                spCM.BBGID = golderRecordDetails.BloombergId;
                spCM.IsAutoStp = (bool)golderRecordDetails.IsAutoStp;
                spCM.InternalID = (long)golderRecordDetails.InternalSecurityId;
                spCM.EventStatus = golderRecordDetails.GoldenRecordStatus;

                if (solaceSettings.SendToTopic)
                {
                    this.solaceMessageListener.SendToTopic(solaceSettings.PositionCheckTopicName, JsonConvert.SerializeObject(spCM));
                }
                else
                {
                    this.solaceMessageListener.SendToQueue(solaceSettings.PositionCheckQueueName, JsonConvert.SerializeObject(spCM));
                }


                res.IsSuccess = true;
                res.Message = "Solace Message send Success";
                res.MessageId = 200;
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.QueueName = queueName;
                logs.Message = JsonConvert.SerializeObject(updatedMessage);
                logs.GoldenRecordDetails = JsonConvert.SerializeObject(golderRecordDetails);
                Logger.LogException(ex, LogType.Error, logs);
                res.IsSuccess = false;
                res.Message = "Solace Message send Failed";
                res.MessageId = 400;
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return res;
        }

        public ResponseParent SendSolaceMessageLinqDB(string queueName, CaapsLinqToDB.DBModels.MT564Message updatedMessage, GoldenRecordMst golderRecordDetails)
        {
            ResponseParent res = new ResponseParent();

            try
            {
                var msgString = JsonConvert.SerializeObject(updatedMessage, Formatting.None, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });
                SolacePositionCheckModel spCM = new SolacePositionCheckModel();
                spCM.Type = "event";
                spCM.GoldenRecordId = golderRecordDetails.GoldenRecordId;
                spCM.EventMsg = msgString;
                spCM.PositionMsg = null;
                spCM.BBGID = golderRecordDetails.BloombergId;
                spCM.IsAutoStp = (bool)golderRecordDetails.IsAutoStp;
                spCM.InternalID = (long)golderRecordDetails.InternalSecurityId;
                spCM.EventStatus = golderRecordDetails.GoldenRecordStatus;

                if (solaceSettings.SendToTopic)
                {
                    this.solaceMessageListener.SendToTopic(solaceSettings.PositionCheckTopicName, JsonConvert.SerializeObject(spCM));
                    this.solaceMessageListener.SendToTopic(solaceSettings.GoldenRecordAPITopicName, JsonConvert.SerializeObject(spCM));
                }
                else
                {
                    this.solaceMessageListener.SendToQueue(solaceSettings.PositionCheckQueueName, JsonConvert.SerializeObject(spCM));
                    this.solaceMessageListener.SendToQueue(solaceSettings.GoldenRecordAPIQueueName, JsonConvert.SerializeObject(spCM));
                }

                res.IsSuccess = true;
                res.Message = "Solace Message send Success";
                res.MessageId = 200;
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.QueueName = queueName;
                logs.Message = JsonConvert.SerializeObject(updatedMessage, Formatting.None, new JsonSerializerSettings { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });
                logs.GoldenRecordDetails = JsonConvert.SerializeObject(golderRecordDetails);
                Logger.LogException(ex, LogType.Error, logs);
                res.IsSuccess = false;
                res.Message = "Solace Message send Failed";
                res.MessageId = 400;
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return res;
        }

        public CaEventElectionOptionsDtl AddDefaultQtyForEventElectionAndPosition(CaEventElectionOptionsDtl c)
        {
            CaEventElectionMapping newEventElectionMapping = new()
            {
                GoldenRecordId = c.GoldenRecordId,
                Mt564SemeRef = c.Mt564SemeRef,
                Mt565SemeRef = null,
                Mt565MsgId = null,
                IsActive = 1,
                EntryBy = c.EntryBy,
                EntryDtTime = DateTime.Now,
                EntryDtTimeUtc = DateTime.UtcNow,
                IsDefault = 1
            };

            this.context.CaEventElectionMappings.Add(newEventElectionMapping);
            this.context.SaveChanges();

            var a = c.TradingAccount.Split('-').First();

            var newAccountId = this.context.AccountMsts.Where(x => x.TradingAccountNumber == a && x.IsActive == 1).Select(x => new
            {
                x.AccountId
            }).FirstOrDefault();

            CaEventElectionOptionsDtl newEventElectionOptionDetail = new()
            {
                CaEventElectionMappingId = newEventElectionMapping.CaEventElectionMappingId,
                GoldenRecordId = c.GoldenRecordId,
                Mt565SemeRef = c.Mt565SemeRef,
                AccountId = newAccountId.AccountId,
                TradingAccount = c.TradingAccount,
                Party = c.Party,
                Place = c.Place,
                OptionNumber = c.OptionNumber,
                OptionType = c.OptionType,
                Qty = c.Qty,
                Price = c.Price,
                Rate = c.Rate,
                CurrencyId = c.CurrencyId,
                Currency = c.Currency,
                ExecutionRequestedDtTime = DateTime.Now,
                Narrative = c.Narrative,
                OptionStatus = c.OptionStatus,
                ExternalComment = c.ExternalComment,
                IsActive = 1,
                EntryBy = c.EntryBy,
                EntryDtTime = DateTime.Now,
                EntryDtTimeUtc = DateTime.UtcNow
            };

            this.context.CaEventElectionOptionsDtls.Add(newEventElectionOptionDetail);
            this.context.SaveChanges();

            MT565MsgFromSwiftProcessor obj = new MT565MsgFromSwiftProcessor();
            obj.CorpRef = Convert.ToString(newEventElectionOptionDetail.GoldenRecordId);
            obj.mt565Ref = newEventElectionOptionDetail.CaEventElectionOptionsDtlId.ToString();
            obj.mt564Ref = c.Mt564SemeRef;
            obj.type = newEventElectionOptionDetail.OptionStatus;
            obj.mt565Json = null;
            obj.isDefault = true;


            if (solaceSettings.SendToTopic)
            {
                this.solaceMessageListener.SendToTopic(solaceSettings.MT565OutBoundTopicName, JsonConvert.SerializeObject(obj));
            }
            else
            {
                this.solaceMessageListener.SendToQueue(solaceSettings.MT565OutBoundQueueName, JsonConvert.SerializeObject(obj));
            }

            newEventElectionOptionDetail.IsSuccess = true;
            newEventElectionOptionDetail.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Submitted);
            newEventElectionOptionDetail.MessageId = (int)ResponseCodeMessage.Submitted;

            return newEventElectionOptionDetail;
        }

        public EventPublishResponse GetEventPublishedDetailsByFromToDate(DateTime fromDate, DateTime toDate, int isHistoricalPending)
        {

            EventPublishResponse publishResponse = new EventPublishResponse();
            try
            {
                //DateTime fromDateTime = DateTime.ParseExact(fromDate, "dd-MM-yyyy", CultureInfo.CurrentCulture);
                //fromDateTime = fromDateTime.Date.Add(new TimeSpan(00, 00, 00));
                //DateTime toDateTime = DateTime.ParseExact(toDate, "dd-MM-yyyy", CultureInfo.CurrentCulture);
                //toDateTime = toDateTime.Date.Add(new TimeSpan(23, 59, 59));

                List<EventPublishedDetail> outboundMessagesSwift = null;
                List<EventPublishedDetail> outboundMessagesEmail = null;
                List<EventPublishedDetail> outboundMessagesEmailByGroup = null;

                if (isHistoricalPending == 0)
                {
                    outboundMessagesSwift = (
                          from oms in this.context.OutboundMsts
                          join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                          join osms in this.context.OutboundSwiftRefMsts on oms.DestinationRefId equals osms.OutboundSwiftRefId
                          join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                          where ((oms.EntryDtTimeUtc >= fromDate) &&
                          (oms.EntryDtTimeUtc <= toDate)) &&
                          (oms.IsActive == 1) &&
                          (ams.IsActive == 1) &&
                          (osms.IsActive == 1) &&
                          oms.Destination == "Swift"
                          select new EventPublishedDetail
                          {
                              BIC = ams.Bic,
                              LegalEntityName = ams.LegalEntityName,
                              //CIBCEntity = ams.CibcEntity,
                              outboundId = oms.OutboundId,
                              DestinationType = oms.Destination,
                              Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                              EventRefId = Convert.ToString(oms.GoldenRecordId),
                              SwiftMessage = "",
                              MessageType = osms.MsgType,
                              ParentCompanyName = ams.ParentCompanyName,
                              SEMERef = osms.SemeRef,
                              EntryDateTimeUtc = oms.EntryDtTimeUtc,
                              IsAutoStp = osms.AutoStp == 1,
                              EventType = grm.EventName,
                              EmailMsg = "",
                              LegalEntityCdrId = oms.LegalEntityCdrId,
                              IsIgnore = oms.IsIgnore,
                              LinkageEventRef = oms.LinkageEventRef,
                              SendAction = oms.SendAction
                          }).Distinct().ToList();

                    //outboundMessagesSwift = outboundMessagesSwift.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();

                    outboundMessagesEmail = (
                          from oms in this.context.OutboundMsts
                          join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                          join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                          join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                          where ((oms.EntryDtTimeUtc >= fromDate) &&
                          (oms.EntryDtTimeUtc <= toDate)) &&
                          (oms.IsActive == 1) &&
                          (ams.IsActive == 1) &&
                          (osms.IsActive == 1) &&
                          oms.Destination == "Email"
                          select new EventPublishedDetail
                          {
                              BIC = ams.Bic,
                              LegalEntityName = ams.LegalEntityName,
                              //CIBCEntity = ams.CibcEntity,
                              outboundId = oms.OutboundId,
                              DestinationType = oms.Destination,
                              Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                              EventRefId = Convert.ToString(oms.GoldenRecordId),
                              SwiftMessage = "",
                              MessageType = osms.MsgType,
                              ParentCompanyName = ams.ParentCompanyName,
                              SEMERef = osms.SemeRef,
                              EntryDateTimeUtc = oms.EntryDtTimeUtc,
                              IsAutoStp = osms.AutoStp == 1,
                              EventType = grm.EventName,
                              EmailMsg = "",
                              LegalEntityCdrId = oms.LegalEntityCdrId,
                              IsIgnore = oms.IsIgnore,
                              LinkageEventRef = oms.LinkageEventRef,
                              SendAction = oms.SendAction
                          }).Distinct().ToList();

                    //outboundMessagesEmail = outboundMessagesEmail.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();

                    // Under CR#112, a new email flow at the group level has been introduced.
                    // GetEventPublishedDetailsByFromToDate for each golden ID will now include records where
                    // emails have been sent at the group level as well.
                    outboundMessagesEmailByGroup = (
                         from oms in this.context.OutboundMsts
                         join ams in this.context.TradingAccountGroups on oms.GroupId equals ams.Group_Id
                         join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                         join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                         where ((oms.EntryDtTimeUtc >= fromDate) &&
                         (oms.EntryDtTimeUtc <= toDate)) &&
                         (oms.IsAccountGroup == 1) &&
                         (oms.IsActive == 1) &&
                         (ams.Is_Active == 1) &&
                         (osms.IsActive == 1) &&
                         oms.Destination == "Email"
                         select new EventPublishedDetail
                         {
                             BIC = "",
                             LegalEntityName = "",
                             //CIBCEntity = ams.CibcEntity,
                             outboundId = oms.OutboundId,
                             DestinationType = oms.Destination,
                             Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                             EventRefId = Convert.ToString(oms.GoldenRecordId),
                             SwiftMessage = "",
                             MessageType = osms.MsgType,
                             ParentCompanyName = "",
                             SEMERef = osms.SemeRef,
                             EntryDateTimeUtc = oms.EntryDtTimeUtc,
                             IsAutoStp = osms.AutoStp == 1,
                             EventType = grm.EventName,
                             EmailMsg = "",
                             LegalEntityCdrId = "",
                             IsIgnore = oms.IsIgnore,
                             LinkageEventRef = oms.LinkageEventRef,
                             SendAction = oms.SendAction,
                             Group_Name = ams.Group_Name,
                             GroupId = ams.Group_Id
                         }).Distinct().ToList();

                }
                else
                {
                    outboundMessagesSwift = (
                          from oms in this.context.OutboundMsts
                          join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                          join osms in this.context.OutboundSwiftRefMsts on oms.DestinationRefId equals osms.OutboundSwiftRefId
                          join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                          where (oms.EntryDtTimeUtc < fromDate) &&
                          (oms.IsActive == 1) &&
                          (ams.IsActive == 1) &&
                          (osms.IsActive == 1) &&
                          oms.Destination == "Swift" &&
                          (oms.OutboundStatus.ToLower() == "swiftnack" || oms.OutboundStatus.ToLower() == "amhnack" || oms.OutboundStatus.ToLower() == "nack")
                          select new EventPublishedDetail
                          {
                              BIC = ams.Bic,
                              LegalEntityName = ams.LegalEntityName,
                              //CIBCEntity = ams.CibcEntity,
                              outboundId = oms.OutboundId,
                              DestinationType = oms.Destination,
                              Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                              EventRefId = Convert.ToString(oms.GoldenRecordId),
                              SwiftMessage = "",
                              MessageType = osms.MsgType,
                              ParentCompanyName = ams.ParentCompanyName,
                              SEMERef = osms.SemeRef,
                              EntryDateTimeUtc = oms.EntryDtTimeUtc,
                              IsAutoStp = osms.AutoStp == 1,
                              EventType = grm.EventName,
                              EmailMsg = "",
                              LegalEntityCdrId = oms.LegalEntityCdrId,
                              IsIgnore = oms.IsIgnore,
                              LinkageEventRef = oms.LinkageEventRef,
                              SendAction = oms.SendAction
                          }).Distinct().ToList();

                    //outboundMessagesSwift = outboundMessagesSwift.GroupBy(x => x.SEMERef).Select(x => x.FirstOrDefault()).ToList();

                    outboundMessagesEmail = (
                          from oms in this.context.OutboundMsts
                          join ams in this.context.AccountMsts on oms.LegalEntityCdrId equals ams.LegalEntityCdrId
                          join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                          join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                          where (oms.EntryDtTimeUtc < fromDate) &&
                          (oms.IsActive == 1) &&
                          (ams.IsActive == 1) &&
                          (osms.IsActive == 1) &&
                          oms.Destination == "Email" &&
                          (oms.OutboundStatus.ToLower() == "swiftnack" || oms.OutboundStatus.ToLower() == "amhnack" || oms.OutboundStatus.ToLower() == "nack")
                          select new EventPublishedDetail
                          {
                              BIC = ams.Bic,
                              LegalEntityName = ams.LegalEntityName,
                              //CIBCEntity = ams.CibcEntity,
                              outboundId = oms.OutboundId,
                              DestinationType = oms.Destination,
                              Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                              EventRefId = Convert.ToString(oms.GoldenRecordId),
                              SwiftMessage = "",
                              MessageType = osms.MsgType,
                              ParentCompanyName = ams.ParentCompanyName,
                              SEMERef = osms.SemeRef,
                              EntryDateTimeUtc = oms.EntryDtTimeUtc,
                              IsAutoStp = osms.AutoStp == 1,
                              EventType = grm.EventName,
                              EmailMsg = "",
                              LegalEntityCdrId = oms.LegalEntityCdrId,
                              IsIgnore = oms.IsIgnore,
                              LinkageEventRef = oms.LinkageEventRef,
                              SendAction = oms.SendAction
                          }).Distinct().ToList();

                    // Under CR#112, a new email flow at the group level has been introduced.
                    // GetEventPublishedDetailsByFromToDate for each golden ID will now include records where
                    // emails have been sent at the group level as well.
                    outboundMessagesEmailByGroup = (
                         from oms in this.context.OutboundMsts
                         join ams in this.context.TradingAccountGroups on oms.GroupId equals ams.Group_Id
                         join osms in this.context.OutboundEmailRefMsts on oms.DestinationRefId equals osms.OutboundEmailRefId
                         join grm in this.context.GoldenRecordMsts on oms.GoldenRecordId equals grm.GoldenRecordId
                         where ((oms.EntryDtTimeUtc >= fromDate) &&
                         (oms.EntryDtTimeUtc <= toDate)) &&
                         (oms.IsActive == 1) &&
                         (oms.IsAccountGroup == 1) &&
                         (ams.Is_Active == 1) &&
                         (osms.IsActive == 1) &&
                         oms.Destination == "Email" &&
                         (oms.OutboundStatus.ToLower() == "swiftnack" || oms.OutboundStatus.ToLower() == "amhnack" || oms.OutboundStatus.ToLower() == "nack")
                         select new EventPublishedDetail
                         {
                             BIC = "",
                             LegalEntityName = "",
                             //CIBCEntity = ams.CibcEntity,
                             outboundId = oms.OutboundId,
                             DestinationType = oms.Destination,
                             Status = oms.OutboundStatus + "," + oms.ErrorMessageText,
                             EventRefId = Convert.ToString(oms.GoldenRecordId),
                             SwiftMessage = "",
                             MessageType = osms.MsgType,
                             ParentCompanyName = "",
                             SEMERef = osms.SemeRef,
                             EntryDateTimeUtc = oms.EntryDtTimeUtc,
                             IsAutoStp = osms.AutoStp == 1,
                             EventType = grm.EventName,
                             EmailMsg = "",
                             LegalEntityCdrId = "",
                             IsIgnore = oms.IsIgnore,
                             LinkageEventRef = oms.LinkageEventRef,
                             SendAction = oms.SendAction,
                             Group_Name = ams.Group_Name,
                             GroupId = ams.Group_Id
                         }).Distinct().ToList();
                }

                publishResponse.PublishDetails = outboundMessagesSwift.Union(outboundMessagesEmail).Union(outboundMessagesEmailByGroup).ToList();
                publishResponse.IsSuccess = true;
                publishResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                publishResponse.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                publishResponse.IsSuccess = false;
                publishResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                publishResponse.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.fromDate = fromDate;
                logs.toDate = toDate;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return publishResponse;
        }

        public List<GoldenRecordInternalChatDetail> GetInternalChatDetailsByGolderRecordId(int GoldenRecordId)
        {
            List<GoldenRecordInternalChatDetail> details = new List<GoldenRecordInternalChatDetail>();
            try
            {
                details = this.context.GoldenRecordInternalChatDetails.Join(this.context.UserMsts, x => x.EntryBy, u => u.UserId, (x, u) => new GoldenRecordInternalChatDetail
                {
                    GoldenRecordId = x.GoldenRecordId,
                    GoldenRecordInternalChatId = x.GoldenRecordInternalChatId,
                    OriginatedFromAction = x.OriginatedFromAction,
                    ChatText = x.ChatText,
                    IsActive = x.IsActive,
                    UserName = u.FullName,
                    EntryBy = x.EntryBy,
                    EntryDtTime = x.EntryDtTime,
                    EntryDtTimeUtc = x.EntryDtTimeUtc,
                }).
                Where(x => x.GoldenRecordId == GoldenRecordId).ToList();

            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = GoldenRecordId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return details;
        }
        public ResponseParent SaveInternalChatDetailsByGolderRecordId(GoldenRecordInternalChatDetail details, int userId)
        {
            ResponseParent res = new ResponseParent();
            try
            {
                details.EntryDtTime = DateTime.Now;
                details.EntryDtTimeUtc = DateTime.UtcNow;
                details.EntryBy = userId;
                details.OriginatedFromAction = "Add";
                this.context.GoldenRecordInternalChatDetails.Add(details);
                this.context.SaveChanges();
                res.IsSuccess = true;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Submitted);
                res.MessageId = (int)ResponseCodeMessage.Submitted;
                sendEventNotification(
                    $"Internal Comment saved",
                    "EVENT_APPROVAL",
                    new
                    {
                        GoldenId = details.GoldenRecordId
                    });
            }
            catch (Exception ex)
            {
                res.IsSuccess = false;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                res.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = JsonConvert.SerializeObject(details);
                logs.userId = userId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return res;
        }

        public DisplayData UpdateDisplayDataBasedOnConditionalFields(DisplayData displayObject, UpdateEventManuallyParameter updateEventManuallyParameter)
        {
            Logger.Log($"UpdateEventManually -> UpdateDisplayDataBasedOnConditionalFields : IsCloneMovement : {updateEventManuallyParameter.IsCloneMovement} FieldCommentUpdateModel : {updateEventManuallyParameter.FieldCommentUpdateModel}", LogType.Info);
            try
            {
                if (!updateEventManuallyParameter.IsCloneMovement)
                {
                    if (updateEventManuallyParameter.FieldCommentUpdateModel != null)
                    {
                        Logger.Log($"UpdateEventManually -> UpdateDisplayDataBasedOnConditionalFields ->FieldCommentUpdateModel  -> Field Details : {JsonConvert.SerializeObject(updateEventManuallyParameter.FieldCommentUpdateModel)}", LogType.Info);
                        FieldCommentUpdateModel fieldCommentUpdateModel = updateEventManuallyParameter.FieldCommentUpdateModel;
                        CaEventConflict conflictValue = null;
                        if (fieldCommentUpdateModel.ConflictId != null && fieldCommentUpdateModel.ConflictId != 0)
                        {
                            conflictValue = this.context.CaEventConflicts.Where(x => x.ConflictId == fieldCommentUpdateModel.ConflictId).FirstOrDefault();
                        }
                        else
                        {
                            conflictValue = this.context.CaEventConflicts.Where(x => x.FieldName == fieldCommentUpdateModel.ConflictIdentifier && x.GoldenRecordId == displayObject.CaapsId).FirstOrDefault();
                        }
                        if (conflictValue != null)
                        {
                            if (fieldCommentUpdateModel.ConflictIdentifier == "optiondetail.depositorycoverexpirationdate.cadatetime"
                              || fieldCommentUpdateModel.ConflictIdentifier == "optiondetail.coverexpirationdate.cadatetime")
                            {
                                updateEventManuallyParameter.DisplayObject.Options.ForEach(option =>
                                {
                                    if (option.CaOptOptionNumber == conflictValue.OptionNumber)
                                    {
                                        if (!string.IsNullOrEmpty(option.CaOptCoverExpirationDate.ToString())
                                        || !string.IsNullOrEmpty(option.CaOptDepositoryCoverExpirationDate.ToString())
                                        || option.CaOptCoverExpirationDateCode == "ONGO"
                                        || option.CaOptDepositoryCoverExpirationDateCode == "ONGO")
                                        {
                                            CaEventConflict leogConflictDetails = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == displayObject.CaapsId && x.FieldName == "eventdetail.letterofguaranteeddelivery.flag").FirstOrDefault();
                                            GoldenRecordMst eventDetail = this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == displayObject.CaapsId).FirstOrDefault();
                                            if ((displayObject.LetterofGuaranteedDelivery == "N" ||
                                            (!string.IsNullOrEmpty(leogConflictDetails.ResolveValue) &&
                                                Newtonsoft.Json.Linq.JObject.Parse(leogConflictDetails.ResolveValue)["flag"].ToString().ToUpper() == "N"))
                                                && IsConditional(eventDetail)
                                            )
                                            {
                                                leogConflictDetails.FieldStatus = 2;
                                                leogConflictDetails.ReviewStatus = 1;
                                                leogConflictDetails.ResolveValue = null;
                                                leogConflictDetails.ClientValue = "";
                                                leogConflictDetails.Comments = "";
                                                displayObject.LetterofGuaranteedDelivery = null;
                                                this.context.CaEventConflicts.Update(leogConflictDetails);
                                                this.context.SaveChanges();
                                            }
                                        }
                                    }
                                });
                            }

                            if (IsPeriodField(fieldCommentUpdateModel.ConflictIdentifier))
                            {
                                switch (fieldCommentUpdateModel.ConflictIdentifier)
                                {
                                    case "optiondetail.revocabilityperiod.fromdatetime":
                                        if (!String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodFromDateCode)
                                            && updateEventManuallyParameter.DisplayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodFromDateCode == "NA")
                                        {
                                            displayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodTo = null;
                                            displayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodToDateCode = "NA";
                                            CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == updateEventManuallyParameter.DisplayObject.CaapsId && x.FieldName == "optiondetail.revocabilityperiod.todatetime" && x.OptionNumber == conflictValue.OptionNumber).FirstOrDefault();
                                            if (objTemp != null)
                                            {
                                                objTemp.Comments = updateEventManuallyParameter.FieldCommentUpdateModel.Comments;
                                                objTemp.ReviewStatus = 3;
                                                this.context.CaEventConflicts.Update(objTemp);
                                                this.context.SaveChanges();
                                            }
                                        }
                                        break;
                                    case "optiondetail.revocabilityperiod.todatetime":
                                        if (!String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodToDateCode)
                                            && updateEventManuallyParameter.DisplayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodToDateCode == "NA")
                                        {
                                            displayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodFrom = null;
                                            displayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptRevocabilityPeriodFromDateCode = "NA";
                                            CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == updateEventManuallyParameter.DisplayObject.CaapsId && x.FieldName == "optiondetail.revocabilityperiod.fromdatetime" && x.OptionNumber == conflictValue.OptionNumber).FirstOrDefault();
                                            if (objTemp != null)
                                            {
                                                objTemp.Comments = updateEventManuallyParameter.FieldCommentUpdateModel.Comments;
                                                objTemp.ReviewStatus = 3;
                                                this.context.CaEventConflicts.Update(objTemp);
                                                this.context.SaveChanges();
                                            }
                                        }
                                        break;
                                    case "eventdetail.claimperiod.fromdatetime":
                                        if (!String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.ClaimPeriodFromDateCode)
                                            && updateEventManuallyParameter.DisplayObject.ClaimPeriodFromDateCode == "NA")
                                        {
                                            displayObject.ClaimPeriodTo = null;
                                            displayObject.ClaimPeriodToDateCode = "NA";
                                            CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == updateEventManuallyParameter.DisplayObject.CaapsId && x.FieldName == "eventdetail.claimperiod.todatetime").FirstOrDefault();
                                            if (objTemp != null)
                                            {
                                                objTemp.Comments = updateEventManuallyParameter.FieldCommentUpdateModel.Comments;
                                                objTemp.ReviewStatus = 3;
                                                this.context.CaEventConflicts.Update(objTemp);
                                                this.context.SaveChanges();
                                            }
                                        }
                                        break;
                                    case "eventdetail.claimperiod.todatetime":
                                        if (!String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.ClaimPeriodToDateCode)
                                            && updateEventManuallyParameter.DisplayObject.ClaimPeriodToDateCode == "NA")
                                        {
                                            displayObject.ClaimPeriodFrom = null;
                                            displayObject.ClaimPeriodFromDateCode = "NA";
                                            CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == updateEventManuallyParameter.DisplayObject.CaapsId && x.FieldName == "eventdetail.claimperiod.fromdatetime").FirstOrDefault();
                                            if (objTemp != null)
                                            {
                                                objTemp.Comments = updateEventManuallyParameter.FieldCommentUpdateModel.Comments;
                                                objTemp.ReviewStatus = 3;
                                                this.context.CaEventConflicts.Update(objTemp);
                                                this.context.SaveChanges();
                                            }
                                        }
                                        break;
                                    case "optiondetail.periodofaction.fromdatetime":
                                        if (!String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptPeriodofActionFromDateCode)
                                            && updateEventManuallyParameter.DisplayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptPeriodofActionFromDateCode == "NA")
                                        {
                                            displayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptPeriodofActionTo = null;
                                            displayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptPeriodofActionToDateCode = "NA";
                                            CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == updateEventManuallyParameter.DisplayObject.CaapsId && x.FieldName == "optiondetail.periodofaction.todatetime" && x.OptionNumber == conflictValue.OptionNumber).FirstOrDefault();
                                            if (objTemp != null)
                                            {
                                                objTemp.Comments = updateEventManuallyParameter.FieldCommentUpdateModel.Comments;
                                                objTemp.ReviewStatus = 3;
                                                this.context.CaEventConflicts.Update(objTemp);
                                                this.context.SaveChanges();
                                            }
                                        }
                                        break;
                                    case "optiondetail.periodofaction.todatetime":
                                        if (!String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptPeriodofActionToDateCode)
                                            && updateEventManuallyParameter.DisplayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptPeriodofActionToDateCode == "NA")
                                        {
                                            displayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptPeriodofActionFrom = null;
                                            displayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptPeriodofActionFromDateCode = "NA";
                                            CaEventConflict objTemp = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == updateEventManuallyParameter.DisplayObject.CaapsId && x.FieldName == "optiondetail.periodofaction.fromdatetime" && x.OptionNumber == conflictValue.OptionNumber).FirstOrDefault();
                                            if (objTemp != null)
                                            {
                                                objTemp.Comments = updateEventManuallyParameter.FieldCommentUpdateModel.Comments;
                                                objTemp.ReviewStatus = 3;
                                                this.context.CaEventConflicts.Update(objTemp);
                                                this.context.SaveChanges();
                                            }
                                        }
                                        break;
                                    default:
                                        break;
                                }
                            }

                        }
                    }
                    else
                    {
                        if (displayObject.Options[displayObject.Options.Count - 1].CaOptWithdrawalAllowed == "Y")
                        {
                            if (String.IsNullOrEmpty(displayObject.Options[displayObject.Options.Count - 1].CaOptRevocabilityPeriodFromDateCode) &&
                                displayObject.Options[displayObject.Options.Count - 1].CaOptRevocabilityPeriodFrom == null)
                            {
                                displayObject.Options[displayObject.Options.Count - 1].CaOptRevocabilityPeriodFromDateCode = "UKWN";
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = JsonConvert.SerializeObject(updateEventManuallyParameter);
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return displayObject;
        }

        public void UpdateGpdDateType(DisplayData displayObject)
        {
            try
            {

                GoldenRecordMst grm = this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == displayObject.CaapsId).FirstOrDefault();
                string[] GPDFields = new string[] { };
                GPDFields = (from cg in this.context.CaEventConfigs
                             join cem in this.context.CaEventTypeMsts on cg.CaEventTypeId equals cem.CaEventTypeId
                             join ce in this.context.CaEventMsts on cg.CaEventMstId equals ce.CaEventMstId
                             where ce.CaEventCode == grm.EventName && cem.CaEventType == grm.EventMvc
                             select cg.GpdDateType).FirstOrDefault().Split(',');

                if (GPDFields.Length == 1)
                {
                    Logger.Log("UpdateGpdDateType : GPDFields.Length == 1 updating  GoldenRecordMsts ", LogType.Info);
                    grm.GpdDateType = GPDFields[0];
                    this.context.GoldenRecordMsts.Update(grm);
                    this.context.SaveChanges();
                }
                else if (GPDFields.Length > 1)
                {

                    string matchDateData = System.IO.File.ReadAllText("./MatchDates.json", Encoding.UTF8);
                    var dateField = System.Text.Json.JsonSerializer.Deserialize<List<MatchDateModel>>(matchDateData);
                    IDictionary<string, DateTime?> objGPDFieldsData = new Dictionary<string, DateTime?>();
                    for (int i = 0; i < GPDFields.Length; i++)
                    {
                        objGPDFieldsData.Add(
                            GPDFields[i],
                            displayObject.GetType().GetProperty(dateField.Where(x => x.Qualifier == GPDFields[i]).FirstOrDefault().MatchDate).GetValue(displayObject) == null ? null :
                            Convert.ToDateTime(displayObject.GetType().GetProperty(dateField.Where(x => x.Qualifier == GPDFields[i]).FirstOrDefault().MatchDate).GetValue(displayObject).ToString())
                            );
                    }

                    if (!objGPDFieldsData.Any(x => x.Value != null))
                    {
                        grm.GpdDateType = "NONE";
                    }
                    else if (objGPDFieldsData.Where(x => x.Value != null).Count() == 1)
                    {
                        grm.GpdDateType = objGPDFieldsData.Where(x => x.Value != null).FirstOrDefault().Key;
                    }
                    else if (objGPDFieldsData.Where(x => x.Value != null).Count() > 1)
                    {
                        grm.GpdDateType = objGPDFieldsData.Where(x => x.Value != null).OrderBy(x => x.Value).FirstOrDefault().Key;
                    }
                    Logger.Log("UpdateGpdDateType : GPDFields.Length > 1 updating  GoldenRecordMsts ", LogType.Info);
                    this.context.GoldenRecordMsts.Update(grm);
                    this.context.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = JsonConvert.SerializeObject(displayObject);
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
        }

        public void CloneMovementConflictChanges(DisplayData displayObject, UpdateEventManuallyParameter updateEventManuallyParameter, int UserId)
        {
            try
            {
                Logger.Log($"CloneMovementConflictChanges : {updateEventManuallyParameter.IsCloneMovement}", LogType.Info);
                if (updateEventManuallyParameter.IsCloneMovement)
                {
                    var optionExceptionData = updateEventManuallyParameter.OptionExceptionModel;
                    List<ConflictIdentifierModel> conflictIdentifierModels = updateEventManuallyParameter.ConflictIdentifierModel;
                    if (conflictIdentifierModels != null)
                    {
                        foreach (var conflictIdentifierModel in conflictIdentifierModels)
                        {
                            CaEventConflict caEventConflict = new CaEventConflict();
                            caEventConflict.GoldenRecordId = displayObject.CaapsId;
                            caEventConflict.FieldName = conflictIdentifierModel.FieldName;
                            caEventConflict.OptionNumber = updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber;
                            caEventConflict.MovementId = conflictIdentifierModel.MovementId;
                            caEventConflict.ExistingSource = optionExceptionData.SourceName;
                            caEventConflict.ClientValue = "";
                            caEventConflict.NewEventId = 0;
                            caEventConflict.NewEventSource = "";
                            caEventConflict.NewEventValue = "";
                            caEventConflict.NewEventOptionNumber = "";
                            caEventConflict.NewEventMovementId = "";
                            caEventConflict.IsActive = 1;
                            caEventConflict.EntryBy = UserId;
                            caEventConflict.EntryDtTime = DateTime.Now;
                            caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                            caEventConflict.FieldStatus = 0;
                            this.context.CaEventConflicts.Add(caEventConflict);
                            this.context.SaveChanges();
                        }
                        this.UpdateOptionException(optionExceptionData);
                        this.UpdateWorkFlowStatus(displayObject.CaapsId, UserRoleConsts.ADMIN, UserId, true,true);
                        if (conflictIdentifierModels.Any(x => x.FieldName.Contains("securityid")))
                        {
                            GoldenRecordSecurityDetail existingObject = this.context.GoldenRecordSecurityDetails.Where(x => x.GoldenRecordId == displayObject.CaapsId
                            && x.OptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber
                            && x.MovementId == conflictIdentifierModels.FirstOrDefault().MovementId).FirstOrDefault();
                            var secIdType = displayObject.Options.Where(x =>
                                            x.CaOptOptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber)
                                            .FirstOrDefault().securityMovement.Where(y =>
                                                y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                    z.FieldName.Contains("securityid"))
                                                .FirstOrDefault().MovementId)
                                            .FirstOrDefault().SMNewSecurityIDType;
                            var secId = displayObject.Options.Where(x =>
                                        x.CaOptOptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber)
                                        .FirstOrDefault().securityMovement.Where(y =>
                                            y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                z.FieldName.Contains("securityid"))
                                            .FirstOrDefault().MovementId)
                                        .FirstOrDefault().SMNewSecurityID;

                           /* Following check is for debit security fields*/
                            if(String.IsNullOrEmpty(secIdType) && String.IsNullOrEmpty(secId))
                            {
                                secIdType = displayObject.Options.Where(x =>
                                            x.CaOptOptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber)
                                            .FirstOrDefault().securityMovement.Where(y =>
                                                y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                    z.FieldName.Contains("securityid"))
                                                .FirstOrDefault().MovementId)
                                            .FirstOrDefault().SMNewDebitSecurityIDType;

                                secId = displayObject.Options.Where(x =>
                                        x.CaOptOptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber)
                                        .FirstOrDefault().securityMovement.Where(y =>
                                            y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                z.FieldName.Contains("securityid"))
                                            .FirstOrDefault().MovementId)
                                        .FirstOrDefault().SMNewDebitSecurityID;
                            }

                            SecurityManager securityManager = new SecurityManager(configuration["ConnectionStrings:CaapsDB"], "MIC");

                            var data = securityManager.FillSecurityData(secIdType, secId, optionExceptionData.SourceName);

                            if (existingObject == null)
                            {
                                existingObject = new GoldenRecordSecurityDetail();
                                existingObject.GoldenRecordId = displayObject.CaapsId;
                                existingObject.OptionNumber = updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber;
                                existingObject.MovementId = conflictIdentifierModels.FirstOrDefault().MovementId;
                                existingObject.CUSIP = data != null && !string.IsNullOrEmpty(data.Cusip) ? data.Cusip : (secIdType == "CUSP" ? secId : "");
                                existingObject.ISIN = data != null && !string.IsNullOrEmpty(data.Isin) ? data.Isin : (secIdType == "ISIN" ? secId : "");
                                existingObject.Sedol = data != null && !string.IsNullOrEmpty(data.Sedol) ? data.Sedol : (secIdType == "Sedol" ? secId : "");
                                existingObject.BloombergId = data != null ? data.BloombergId : "";
                                existingObject.ShortName = data != null ? data.ShortName : "";
                                existingObject.LongName = data != null ? data.LongName : "";
                                existingObject.IsActive = 1;
                                existingObject.EntryBy = UserId;
                                existingObject.EntryDtTime = DateTime.Now;
                                existingObject.EntryDtTimeUtc = DateTime.UtcNow;
                                this.context.GoldenRecordSecurityDetails.Add(existingObject);
                            }
                            else
                            {
                                if ((secIdType == "CUSP" && secId != existingObject.CUSIP)
                                        || (secIdType == "ISIN" && secId != existingObject.ISIN)
                                        || (secIdType == "Sedol" && secId != existingObject.Sedol)
                                        )
                                {
                                    existingObject.CUSIP = secIdType == "CUSP" ? secId : "";
                                    existingObject.ISIN = secIdType == "ISIN" ? secId : "";
                                    existingObject.Sedol = secIdType == "Sedol" ? secId : "";
                                    existingObject.BloombergId = data != null ? data.BloombergId : "";
                                    existingObject.ShortName = data != null ? data.ShortName : "";
                                    existingObject.LongName = data != null ? data.LongName : "";
                                    this.context.GoldenRecordSecurityDetails.Update(existingObject);
                                }
                            }
                            this.context.SaveChanges();
                        }
                    }
                }
                /*
                    (CR) #119 Introduces the Add Movement functionality .
                 */
                if (updateEventManuallyParameter.IsAddMovement)
                {
                    AllSourceResponse sources = GetAllSourceByGoldenId(displayObject.CaapsId);
                    List<ConflictIdentifierModel> conflictIdentifierModels = updateEventManuallyParameter.ConflictIdentifierModel;
                    if (conflictIdentifierModels != null)
                    {
                        foreach (var conflictIdentifierModel in conflictIdentifierModels)
                        {
                            CaEventConflict caEventConflict = new CaEventConflict();
                            caEventConflict.GoldenRecordId = displayObject.CaapsId;
                            caEventConflict.FieldName = conflictIdentifierModel.FieldName;
                            caEventConflict.OptionNumber = updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber;
                            caEventConflict.MovementId = conflictIdentifierModel.MovementId;
                            caEventConflict.ExistingSource = sources.Sources?.FirstOrDefault().EventSourceName;
                            caEventConflict.ClientValue = "";
                            caEventConflict.NewEventId = 0;
                            caEventConflict.NewEventSource = "";
                            caEventConflict.NewEventValue = "";
                            caEventConflict.NewEventOptionNumber = "";
                            caEventConflict.NewEventMovementId = "";
                            caEventConflict.IsActive = 1;
                            caEventConflict.EntryBy = UserId;
                            caEventConflict.EntryDtTime = DateTime.Now;
                            caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                            caEventConflict.FieldStatus = 0;
                            this.context.CaEventConflicts.Add(caEventConflict);
                            this.context.SaveChanges();
                        }
                        this.UpdateWorkFlowStatus(displayObject.CaapsId, UserRoleConsts.ADMIN, UserId, true,true);
                        if (conflictIdentifierModels.Any(x => x.FieldName.Contains("securityid")))
                        {
                            GoldenRecordSecurityDetail existingObject = this.context.GoldenRecordSecurityDetails.Where(x => x.GoldenRecordId == displayObject.CaapsId
                            && x.OptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber
                            && x.MovementId == conflictIdentifierModels.FirstOrDefault().MovementId).FirstOrDefault();
                            var secIdType = displayObject.Options.Where(x =>
                                            x.CaOptOptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber)
                                            .FirstOrDefault().securityMovement.Where(y =>
                                                y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                    z.FieldName.Contains("securityid"))
                                                .FirstOrDefault().MovementId)
                                            .FirstOrDefault().SMNewSecurityIDType;
                            var secId = displayObject.Options.Where(x =>
                                        x.CaOptOptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber)
                                        .FirstOrDefault().securityMovement.Where(y =>
                                            y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                z.FieldName.Contains("securityid"))
                                            .FirstOrDefault().MovementId)
                                        .FirstOrDefault().SMNewSecurityID;

                            if (String.IsNullOrEmpty(secIdType) && String.IsNullOrEmpty(secId))
                            {
                                secIdType = displayObject.Options.Where(x =>
                                            x.CaOptOptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber)
                                            .FirstOrDefault().securityMovement.Where(y =>
                                                y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                    z.FieldName.Contains("securityid"))
                                                .FirstOrDefault().MovementId)
                                            .FirstOrDefault().SMNewDebitSecurityIDType;

                                secId = displayObject.Options.Where(x =>
                                        x.CaOptOptionNumber == updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber)
                                        .FirstOrDefault().securityMovement.Where(y =>
                                            y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                z.FieldName.Contains("securityid"))
                                            .FirstOrDefault().MovementId)
                                        .FirstOrDefault().SMNewDebitSecurityID;
                            }

                            SecurityManager securityManager = new SecurityManager(configuration["ConnectionStrings:CaapsDB"], "MIC");

                            var data = securityManager.FillSecurityData(secIdType, secId, sources.Sources?.FirstOrDefault().EventSourceName);

                            if (existingObject == null)
                            {
                                existingObject = new GoldenRecordSecurityDetail();
                                existingObject.GoldenRecordId = displayObject.CaapsId;
                                existingObject.OptionNumber = updateEventManuallyParameter.LinkedClientOptionData.CaOptOptionNumber;
                                existingObject.MovementId = conflictIdentifierModels.FirstOrDefault().MovementId;
                                existingObject.CUSIP = data != null && !string.IsNullOrEmpty(data.Cusip) ? data.Cusip : (secIdType == "CUSP" ? secId : "");
                                existingObject.ISIN = data != null && !string.IsNullOrEmpty(data.Isin) ? data.Isin : (secIdType == "ISIN" ? secId : "");
                                existingObject.Sedol = data != null && !string.IsNullOrEmpty(data.Sedol) ? data.Sedol : (secIdType == "Sedol" ? secId : "");
                                existingObject.BloombergId = data != null ? data.BloombergId : "";
                                existingObject.ShortName = data != null ? data.ShortName : "";
                                existingObject.LongName = data != null ? data.LongName : "";
                                existingObject.IsActive = 1;
                                existingObject.EntryBy = UserId;
                                existingObject.EntryDtTime = DateTime.Now;
                                existingObject.EntryDtTimeUtc = DateTime.UtcNow;
                                this.context.GoldenRecordSecurityDetails.Add(existingObject);
                            }
                            else
                            {
                                if ((secIdType == "CUSP" && secId != existingObject.CUSIP)
                                        || (secIdType == "ISIN" && secId != existingObject.ISIN)
                                        || (secIdType == "Sedol" && secId != existingObject.Sedol)
                                        )
                                {
                                    existingObject.CUSIP = secIdType == "CUSP" ? secId : "";
                                    existingObject.ISIN = secIdType == "ISIN" ? secId : "";
                                    existingObject.Sedol = secIdType == "Sedol" ? secId : "";
                                    existingObject.BloombergId = data != null ? data.BloombergId : "";
                                    existingObject.ShortName = data != null ? data.ShortName : "";
                                    existingObject.LongName = data != null ? data.LongName : "";
                                    this.context.GoldenRecordSecurityDetails.Update(existingObject);
                                }
                            }
                            this.context.SaveChanges();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = JsonConvert.SerializeObject(updateEventManuallyParameter);
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
        }

        public int AddOrCloneOption(DisplayData displayObject, UpdateEventManuallyParameter updateEventManuallyParameter, int UserId, int sendSolaceMessage)
        {
            try
            {
                Logger.Log($"AddOrCloneOption : IsCloneMovement : {updateEventManuallyParameter.IsCloneMovement} FieldCommentUpdateModel:{updateEventManuallyParameter.FieldCommentUpdateModel}", LogType.Info);
                if (!updateEventManuallyParameter.IsCloneMovement && !updateEventManuallyParameter.IsAddMovement)
                {
                    if (updateEventManuallyParameter.FieldCommentUpdateModel == null)
                    {

                        var optionExceptionData = updateEventManuallyParameter.OptionExceptionModel;
                        var cloneFromSource = updateEventManuallyParameter.CloneFromSource;
                        var SourceEventID = "";
                        if (cloneFromSource != null)
                        {
                            CaOptionException availableCloneException = this.context.CaOptionExceptions.Where(x => x.GoldenRecordId == displayObject.CaapsId && x.SourceName == cloneFromSource.SourceName
                            && x.ExceptionType == "Unlinked Source Option" && x.OptionNumber == cloneFromSource.OptionNumber && x.ExceptionStatus == "Open").FirstOrDefault();
                            if (availableCloneException != null)
                            {
                                availableCloneException.ExceptionStatus = "User Resolved";
                                this.context.CaOptionExceptions.Update(availableCloneException);
                                this.context.SaveChanges();
                            }
                            SourceEventID = this.context.GoldenRecordSourceEventMappings.Where(x => x.GoldenRecordId == displayObject.CaapsId && x.SourceName == cloneFromSource.SourceName)
                                .OrderByDescending(x => x.EntryDtTimeUtc).FirstOrDefault().SemeRef;
                        }
                        //Add entry in link options table and event conflict table for newly created option
                        if (displayObject.Options != null && displayObject.Options.ToList().Count() > 0)
                        {
                            var newlyCreatedOption = displayObject.Options.ToList().ElementAt(displayObject.Options.ToList().Count() - 1); //new option will be at last index
                            if (newlyCreatedOption.CaOptOptionNumber != null)
                            {
                                AllSourceResponse sources = GetAllSourceByGoldenId(displayObject.CaapsId);
                                foreach (var source in sources.Sources)
                                {
                                    if (optionExceptionData != null && source.EventSourceName == optionExceptionData.SourceName)
                                    {
                                        StringBuilder sourceEventStringBuilder = new StringBuilder(displayObject.CaapsId.ToString());
                                        CaOptionLink caOptionLink = new CaOptionLink();
                                        caOptionLink.GoldenRecordId = displayObject.CaapsId;
                                        caOptionLink.ClientLinkStatus = "Linked";
                                        caOptionLink.SourceLinkStatus = "Linked";
                                        caOptionLink.ClientOptionStatus = "";
                                        caOptionLink.SourceOptionStatus = "";
                                        caOptionLink.ClientOptionNumber = newlyCreatedOption.CaOptOptionNumber;
                                        caOptionLink.SourceName = source.EventSourceName;
                                        caOptionLink.SourceBic = optionExceptionData.SourceBic;
                                        caOptionLink.SourceEventId = optionExceptionData.SourceEventId;
                                        caOptionLink.SourceOptionNumber = optionExceptionData.OptionNumber;
                                        caOptionLink.IsActive = 1;
                                        caOptionLink.EntryBy = UserId;
                                        caOptionLink.EntryDtTime = DateTime.Now;
                                        caOptionLink.EntryDtTimeUtc = DateTime.UtcNow;

                                        CaOptionLink existingCaOptionLink = this.context.CaOptionLinks.Where(x => x.GoldenRecordId == displayObject.CaapsId && x.ClientOptionNumber == newlyCreatedOption.CaOptOptionNumber).FirstOrDefault();
                                        if (existingCaOptionLink == null)
                                        {
                                            this.context.CaOptionLinks.Add(caOptionLink);
                                            this.context.SaveChanges();
                                        }
                                    }
                                    else if (cloneFromSource != null && source.EventSourceName == cloneFromSource.SourceName)
                                    {
                                        StringBuilder sourceEventStringBuilder = new StringBuilder(displayObject.CaapsId.ToString());
                                        CaOptionLink caOptionLink = new CaOptionLink();
                                        caOptionLink.GoldenRecordId = displayObject.CaapsId;
                                        caOptionLink.ClientLinkStatus = "Linked";
                                        caOptionLink.SourceLinkStatus = "Linked";
                                        caOptionLink.ClientOptionStatus = "";
                                        caOptionLink.SourceOptionStatus = "";
                                        caOptionLink.ClientOptionNumber = newlyCreatedOption.CaOptOptionNumber;
                                        caOptionLink.SourceName = source.EventSourceName;
                                        caOptionLink.SourceBic = "";
                                        caOptionLink.SourceEventId = SourceEventID;
                                        caOptionLink.SourceOptionNumber = cloneFromSource.OptionNumber;
                                        caOptionLink.IsActive = 1;
                                        caOptionLink.EntryBy = UserId;
                                        caOptionLink.EntryDtTime = DateTime.Now;
                                        caOptionLink.EntryDtTimeUtc = DateTime.UtcNow;

                                        CaOptionLink existingCaOptionLink = this.context.CaOptionLinks.Where(x => x.GoldenRecordId == displayObject.CaapsId && x.ClientOptionNumber == newlyCreatedOption.CaOptOptionNumber).FirstOrDefault();
                                        if (existingCaOptionLink == null)
                                        {
                                            this.context.CaOptionLinks.Add(caOptionLink);
                                            this.context.SaveChanges();
                                        }
                                    }
                                    else
                                    {
                                        StringBuilder sourceEventStringBuilder = new StringBuilder(displayObject.CaapsId.ToString());
                                        CaOptionLink caOptionLink = new CaOptionLink();
                                        caOptionLink.GoldenRecordId = displayObject.CaapsId;
                                        caOptionLink.ClientLinkStatus = newlyCreatedOption.CaOptOptionNumber == "999" ? "NoLink" : "Unlinked";
                                        caOptionLink.SourceLinkStatus = "";
                                        caOptionLink.ClientOptionStatus = "";
                                        caOptionLink.SourceOptionStatus = "";
                                        caOptionLink.ClientOptionNumber = newlyCreatedOption.CaOptOptionNumber;
                                        caOptionLink.SourceName = source.EventSourceName;
                                        caOptionLink.SourceBic = "";
                                        caOptionLink.SourceEventId = sourceEventStringBuilder.Append("_").Append(newlyCreatedOption.CaOptOptionNumber).ToString();
                                        caOptionLink.SourceOptionNumber = "";
                                        caOptionLink.IsActive = 1;
                                        caOptionLink.EntryBy = UserId;
                                        caOptionLink.EntryDtTime = DateTime.Now;
                                        caOptionLink.EntryDtTimeUtc = DateTime.UtcNow;

                                        CaOptionLink existingCaOptionLink = this.context.CaOptionLinks.Where(x => x.GoldenRecordId == displayObject.CaapsId && x.ClientOptionNumber == newlyCreatedOption.CaOptOptionNumber && x.SourceName == source.EventSourceName).FirstOrDefault();
                                        if (existingCaOptionLink == null)
                                        {
                                            this.context.CaOptionLinks.Add(caOptionLink);
                                            this.context.SaveChanges();
                                        }
                                    }
                                }

                                List<ConflictIdentifierModel> conflictIdentifierModels = updateEventManuallyParameter.ConflictIdentifierModel;
                                if (conflictIdentifierModels != null)
                                {
                                    foreach (var conflictIdentifierModel in conflictIdentifierModels)
                                    {
                                        CaEventConflict caEventConflict = new CaEventConflict();
                                        caEventConflict.GoldenRecordId = displayObject.CaapsId;
                                        caEventConflict.FieldName = conflictIdentifierModel.FieldName;
                                        caEventConflict.OptionNumber = newlyCreatedOption.CaOptOptionNumber;
                                        caEventConflict.MovementId = conflictIdentifierModel.MovementId;
                                        caEventConflict.ExistingSource = optionExceptionData != null ? optionExceptionData.SourceName :
                                            cloneFromSource != null ? cloneFromSource.SourceName : sources.Sources?.FirstOrDefault().EventSourceName;
                                        caEventConflict.ClientValue = "";
                                        caEventConflict.NewEventId = 0;
                                        caEventConflict.NewEventSource = "";
                                        caEventConflict.NewEventValue = "";
                                        caEventConflict.NewEventOptionNumber = "";
                                        caEventConflict.NewEventMovementId = "";
                                        caEventConflict.IsActive = 1;
                                        caEventConflict.EntryBy = UserId;
                                        caEventConflict.EntryDtTime = DateTime.Now;
                                        caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                                        if (conflictIdentifierModel.FieldName == "optiondetail.revocabilityperiod.todatetime")
                                        {
                                            if (newlyCreatedOption.CaOptWithdrawalAllowed == "Y" && newlyCreatedOption.CaOptOptionNumber != "999")
                                            {
                                                if (String.IsNullOrEmpty(newlyCreatedOption.CaOptRevocabilityPeriodTo.ToString()))
                                                {
                                                    caEventConflict.FieldStatus = 2;
                                                    caEventConflict.ReviewStatus = 1;
                                                }
                                                else
                                                {
                                                    caEventConflict.FieldStatus = 0;
                                                    caEventConflict.ReviewStatus = 4;
                                                }
                                            }
                                            else
                                            {
                                                caEventConflict.FieldStatus = 0;
                                                caEventConflict.ReviewStatus = 4;
                                            }
                                        }
                                        else if (conflictIdentifierModel.FieldName == "optiondetail.narrativeversion.narrative")
                                        {
                                            if (newlyCreatedOption.CaOptOptionType == "OTHR")
                                            {
                                                if (String.IsNullOrEmpty(newlyCreatedOption.CaOptOptionComments))
                                                {
                                                    caEventConflict.FieldStatus = 2;
                                                    caEventConflict.ReviewStatus = 1;
                                                }
                                                else
                                                {
                                                    caEventConflict.FieldStatus = 0;
                                                    caEventConflict.ReviewStatus = 4;
                                                }
                                            }
                                            else
                                            {
                                                caEventConflict.FieldStatus = 0;
                                                caEventConflict.ReviewStatus = 4;
                                            }
                                        }
                                        else if (conflictIdentifierModel.FieldName == "cashmovement.genericcashpricepaid"
                                            && IsDebitRequired(displayObject))
                                        {
                                            if ((newlyCreatedOption.cashMovements.Where(x => x.CMCashNumber == conflictIdentifierModel.MovementId)
                                                .FirstOrDefault().CMCreditOrDebit == "DEBT")
                                                &&
                                                String.IsNullOrEmpty(newlyCreatedOption.cashMovements.Where(x => x.CMCashNumber == conflictIdentifierModel.MovementId)
                                                .FirstOrDefault().CMPricePaid))
                                            {
                                                caEventConflict.FieldStatus = 2;
                                                caEventConflict.ReviewStatus = 1;
                                            }
                                            else
                                            {
                                                caEventConflict.FieldStatus = 0;
                                                caEventConflict.ReviewStatus = 4;
                                            }
                                        }
                                        else if (conflictIdentifierModel.FieldName == "optiondetail.coverexpirationdate.cadatetime"
                                            || conflictIdentifierModel.FieldName == "optiondetail.depositorycoverexpirationdate.cadatetime")
                                        {
                                            CaEventConflict leogObj = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == displayObject.CaapsId && x.FieldName == "eventdetail.letterofguaranteeddelivery.flag").FirstOrDefault();
                                            if (leogObj.ReviewStatus == 2)
                                            {
                                                if (Newtonsoft.Json.Linq.JObject.Parse(leogObj.ResolveValue)["flag"] != null &&
                                                    Newtonsoft.Json.Linq.JObject.Parse(leogObj.ResolveValue)["flag"].ToString().ToUpper() == "Y")
                                                {
                                                    if (conflictIdentifierModel.FieldName == "optiondetail.coverexpirationdate.cadatetime")
                                                    {
                                                        if (String.IsNullOrEmpty(newlyCreatedOption.CaOptCoverExpirationDate.ToString())
                                                            && String.IsNullOrEmpty(newlyCreatedOption.CaOptCoverExpirationDateCode) && newlyCreatedOption.CaOptOptionNumber != "999")
                                                        {
                                                            caEventConflict.FieldStatus = 2;
                                                            caEventConflict.ReviewStatus = 1;
                                                        }
                                                        else
                                                        {
                                                            caEventConflict.FieldStatus = 0;
                                                            caEventConflict.ReviewStatus = 4;
                                                        }
                                                    }
                                                    else if (conflictIdentifierModel.FieldName == "optiondetail.depositorycoverexpirationdate.cadatetime")
                                                    {
                                                        if (String.IsNullOrEmpty(newlyCreatedOption.CaOptDepositoryCoverExpirationDate.ToString())
                                                        && String.IsNullOrEmpty(newlyCreatedOption.CaOptDepositoryCoverExpirationDateCode) && newlyCreatedOption.CaOptOptionNumber != "999")
                                                        {
                                                            caEventConflict.FieldStatus = 2;
                                                            caEventConflict.ReviewStatus = 1;
                                                        }
                                                        else
                                                        {
                                                            caEventConflict.FieldStatus = 0;
                                                            caEventConflict.ReviewStatus = 4;
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    caEventConflict.FieldStatus = 0;
                                                    caEventConflict.ReviewStatus = 4;
                                                }
                                            }
                                            else
                                            {
                                                if (displayObject.LetterofGuaranteedDelivery == null)
                                                {
                                                    caEventConflict.FieldStatus = 0;
                                                    caEventConflict.ReviewStatus = 4;
                                                }
                                                else
                                                {
                                                    if (displayObject.LetterofGuaranteedDelivery.ToUpper() == "Y")
                                                    {
                                                        if (conflictIdentifierModel.FieldName == "optiondetail.coverexpirationdate.cadatetime")
                                                        {
                                                            if (String.IsNullOrEmpty(newlyCreatedOption.CaOptCoverExpirationDate.ToString())
                                                                && String.IsNullOrEmpty(newlyCreatedOption.CaOptCoverExpirationDateCode) && newlyCreatedOption.CaOptOptionNumber != "999")
                                                            {
                                                                caEventConflict.FieldStatus = 2;
                                                                caEventConflict.ReviewStatus = 1;
                                                            }
                                                            else
                                                            {
                                                                caEventConflict.FieldStatus = 0;
                                                                caEventConflict.ReviewStatus = 4;
                                                            }
                                                        }
                                                        else if (conflictIdentifierModel.FieldName == "optiondetail.depositorycoverexpirationdate.cadatetime")
                                                        {
                                                            if (String.IsNullOrEmpty(newlyCreatedOption.CaOptDepositoryCoverExpirationDate.ToString())
                                                            && String.IsNullOrEmpty(newlyCreatedOption.CaOptDepositoryCoverExpirationDateCode) && newlyCreatedOption.CaOptOptionNumber != "999")
                                                            {
                                                                caEventConflict.FieldStatus = 2;
                                                                caEventConflict.ReviewStatus = 1;
                                                            }
                                                            else
                                                            {
                                                                caEventConflict.FieldStatus = 0;
                                                                caEventConflict.ReviewStatus = 4;
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        caEventConflict.FieldStatus = 0;
                                                        caEventConflict.ReviewStatus = 4;
                                                    }
                                                }
                                            }
                                        }
                                        else
                                        {
                                            caEventConflict.FieldStatus = 0;
                                            caEventConflict.ReviewStatus = 4;
                                        }
                                        this.context.CaEventConflicts.Add(caEventConflict);
                                        this.context.SaveChanges();
                                    }
                                    if (optionExceptionData != null)
                                    {
                                        CaOptionException UpdatedOptionException = this.context.CaOptionExceptions.Where(x => x.CaOptionExceptionId == optionExceptionData.CaOptionExceptionId).FirstOrDefault();
                                        UpdatedOptionException.ExceptionStatus = "User Resolved";
                                        this.context.CaOptionExceptions.Update(UpdatedOptionException);
                                        this.context.SaveChanges();
                                    }
                                    this.UpdateWorkFlowStatus(displayObject.CaapsId, UserRoleConsts.ADMIN, UserId, true,true);

                                    if (conflictIdentifierModels.Any(x => x.FieldName.Contains("securityid")))
                                    {
                                        var optSecLength = conflictIdentifierModels.Any(z => z.FieldName.Contains("optiondetail.securityid"));
                                        var secLength = conflictIdentifierModels.Where(z => z.FieldName.Contains("securityid") && !z.FieldName.Contains("optiondetail.securityid")).ToList().Count / 2;

                                        if (optSecLength)
                                        {
                                            var optSecIdType = displayObject.Options.Where(x =>
                                                            x.CaOptOptionNumber == newlyCreatedOption.CaOptOptionNumber)
                                                            .FirstOrDefault()?.CaOptSecurityIDType;
                                            var optSecId = displayObject.Options.Where(x =>
                                                        x.CaOptOptionNumber == newlyCreatedOption.CaOptOptionNumber)
                                                        .FirstOrDefault()?.CaOptSecurityID;

                                            if (!String.IsNullOrEmpty(optSecIdType) && !String.IsNullOrEmpty(optSecId))
                                            {
                                                GoldenRecordSecurityDetail existingObject = null;
                                                SecurityManager securityManager = new SecurityManager(configuration["ConnectionStrings:CaapsDB"], "MIC");
                                                var data = securityManager.FillSecurityData(optSecIdType, optSecId,
                                                    optionExceptionData != null ? optionExceptionData.SourceName :
                                                    cloneFromSource != null ? cloneFromSource.SourceName :
                                                    ""
                                                    );

                                                if (existingObject == null)
                                                {
                                                    existingObject = new GoldenRecordSecurityDetail();
                                                    existingObject.GoldenRecordId = displayObject.CaapsId;
                                                    existingObject.OptionNumber = newlyCreatedOption.CaOptOptionNumber;
                                                    existingObject.MovementId = "";
                                                    existingObject.CUSIP = data != null && !string.IsNullOrEmpty(data.Cusip) ? data.Cusip : (optSecIdType == "CUSP" ? optSecId : "");
                                                    existingObject.ISIN = data != null && !string.IsNullOrEmpty(data.Isin) ? data.Isin : (optSecIdType == "ISIN" ? optSecId : "");
                                                    existingObject.Sedol = data != null && !string.IsNullOrEmpty(data.Sedol) ? data.Sedol : (optSecIdType == "Sedol" ? optSecId : "");
                                                    existingObject.BloombergId = data != null ? data.BloombergId : "";
                                                    existingObject.ShortName = data != null ? data.ShortName : "";
                                                    existingObject.LongName = data != null ? data.LongName : "";
                                                    existingObject.IsActive = 1;
                                                    existingObject.EntryBy = UserId;
                                                    existingObject.EntryDtTime = DateTime.Now;
                                                    existingObject.EntryDtTimeUtc = DateTime.UtcNow;
                                                    this.context.GoldenRecordSecurityDetails.Add(existingObject);
                                                }
                                                this.context.SaveChanges();
                                            }
                                        }

                                        for (var i = 0; i < secLength; i++)
                                        {
                                            GoldenRecordSecurityDetail existingObject = null;
                                            var secIdType = displayObject.Options.Where(x =>
                                                            x.CaOptOptionNumber == newlyCreatedOption.CaOptOptionNumber)
                                                            .FirstOrDefault()?.securityMovement.Where(y =>
                                                                y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                                    z.FieldName.Contains("securityid") &&
                                                                    !z.FieldName.Contains("optiondetail.securityid")
                                                                    ).ToList()[i * 2]?.MovementId)
                                                            .FirstOrDefault()?.SMNewSecurityIDType;
                                            var secId = displayObject.Options.Where(x =>
                                                        x.CaOptOptionNumber == newlyCreatedOption.CaOptOptionNumber)
                                                        .FirstOrDefault()?.securityMovement.Where(y =>
                                                            y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                                z.FieldName.Contains("securityid") &&
                                                                !z.FieldName.Contains("optiondetail.securityid")
                                                                ).ToList()[i * 2]?.MovementId)
                                                        .FirstOrDefault()?.SMNewSecurityID;

                                            /* Following check is for debit security fields*/
                                            if (String.IsNullOrEmpty(secIdType) && String.IsNullOrEmpty(secId))
                                            {
                                                secIdType = displayObject.Options.Where(x =>
                                                            x.CaOptOptionNumber == newlyCreatedOption.CaOptOptionNumber)
                                                            .FirstOrDefault()?.securityMovement.Where(y =>
                                                                y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                                    z.FieldName.Contains("securityid") &&
                                                                    !z.FieldName.Contains("optiondetail.securityid")
                                                                    ).ToList()[i * 2]?.MovementId)
                                                            .FirstOrDefault()?.SMNewDebitSecurityIDType;

                                                secId = displayObject.Options.Where(x =>
                                                        x.CaOptOptionNumber == newlyCreatedOption.CaOptOptionNumber)
                                                        .FirstOrDefault()?.securityMovement.Where(y =>
                                                            y.SMSecurityNumber == conflictIdentifierModels.Where(z =>
                                                                z.FieldName.Contains("securityid") &&
                                                                !z.FieldName.Contains("optiondetail.securityid")
                                                                ).ToList()[i * 2]?.MovementId)
                                                        .FirstOrDefault()?.SMNewDebitSecurityID;
                                            }

                                            if (!String.IsNullOrEmpty(secIdType) && !String.IsNullOrEmpty(secId))
                                            {
                                                SecurityManager securityManager = new SecurityManager(configuration["ConnectionStrings:CaapsDB"], "MIC");
                                                var data = securityManager.FillSecurityData(secIdType, secId,
                                                    optionExceptionData != null ? optionExceptionData.SourceName :
                                                    cloneFromSource != null ? cloneFromSource.SourceName :
                                                    ""
                                                    );

                                                if (existingObject == null)
                                                {
                                                    existingObject = new GoldenRecordSecurityDetail();
                                                    existingObject.GoldenRecordId = displayObject.CaapsId;
                                                    existingObject.OptionNumber = newlyCreatedOption.CaOptOptionNumber;
                                                    existingObject.MovementId = conflictIdentifierModels.Where(z =>
                                                                z.FieldName.Contains("securityid")
                                                                && !z.FieldName.Contains("optiondetail.securityid")
                                                                ).ToList()[i * 2]?.MovementId;
                                                    existingObject.CUSIP = data != null && !string.IsNullOrEmpty(data.Cusip) ? data.Cusip : (secIdType == "CUSP" ? secId : "");
                                                    existingObject.ISIN = data != null && !string.IsNullOrEmpty(data.Isin) ? data.Isin : (secIdType == "ISIN" ? secId : "");
                                                    existingObject.Sedol = data != null && !string.IsNullOrEmpty(data.Sedol) ? data.Sedol : (secIdType == "Sedol" ? secId : "");
                                                    existingObject.BloombergId = data != null ? data.BloombergId : "";
                                                    existingObject.ShortName = data != null ? data.ShortName : "";
                                                    existingObject.LongName = data != null ? data.LongName : "";
                                                    existingObject.IsActive = 1;
                                                    existingObject.EntryBy = UserId;
                                                    existingObject.EntryDtTime = DateTime.Now;
                                                    existingObject.EntryDtTimeUtc = DateTime.UtcNow;
                                                    this.context.GoldenRecordSecurityDetails.Add(existingObject);
                                                }
                                                this.context.SaveChanges();
                                            }
                                        }
                                    }

                                }
                                //update option exception status
                                UpdateOptionExceptionStatus(displayObject.CaapsId, UserId, true);

                                sendSolaceMessage = 1;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = JsonConvert.SerializeObject(updateEventManuallyParameter);
                Logger.LogException(ex, LogType.Error, logs);
                if (ex.InnerException != null)
                {
                    if (!string.IsNullOrEmpty(ex.InnerException.Message))
                    Logger.LogException(ex, LogType.Error, ex.InnerException.Message);
                }
                

                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return sendSolaceMessage;
        }

        public ResponseParent UpdateEventManually(UpdateEventManuallyParameter updateEventManuallyParameter, int UserId)
        {
            Logger.Log("UpdateEventManually : Request Received", LogType.Info);
            ResponseParent res = new ResponseParent();
            bool conditionalFieldChange = false;
            try
            {
                DisplayData displayObject = updateEventManuallyParameter.DisplayObject;

                //For Conditional field update based on LEOG - Start
                displayObject = UpdateDisplayDataBasedOnConditionalFields(displayObject, updateEventManuallyParameter);
                //For Conditional field update based on LEOG - End
                Logger.Log("UpdateEventManually : UpdateDisplayDataBasedOnConditionalFields Done ,Now updating MT564Message", LogType.Info);
                UpdateMT564MessageModel model = this.linqToDbHelper.UpdateMT564Message(displayObject);
                CaapsLinqToDB.DBModels.MT564Message UpdatedMessage = model.UpdatedMessage;
                AdditionalInfoFlags flagDetails = this.linqToDbHelper.getAdditionFlags(UpdatedMessage);
                int sendSolaceMessage = 0;

                //For GPD Date Type update based on GPD Date - Start
                Logger.Log("UpdateEventManually -> UpdateGpdDateType ", LogType.Info);
                UpdateGpdDateType(displayObject);
                Boolean isGPDUpdateorNot = this.setGPDDate(model.Message, model.UpdatedMessage, displayObject.EventName, displayObject.EventMvc);
                //For GPD Date Type update based on GPD Date - End

                //Update Comment in conflict table
                if (!updateEventManuallyParameter.IsCloneMovement)
                {
                    if (updateEventManuallyParameter.FieldCommentUpdateModel != null)
                    {
                        FieldCommentUpdateModel fieldCommentUpdateModel = updateEventManuallyParameter.FieldCommentUpdateModel;
                        //CaEventConflict conflictValue = this.context.CaEventConflicts.Where(x => x.FieldName == fieldCommentUpdateModel.ConflictIdentifier && x.GoldenRecordId == displayObject.CaapsId).FirstOrDefault();
                        CaEventConflict conflictValue = null;
                        if (fieldCommentUpdateModel.ConflictId != null && fieldCommentUpdateModel.ConflictId != 0)
                        {
                            conflictValue = this.context.CaEventConflicts.Where(x => x.ConflictId == fieldCommentUpdateModel.ConflictId).FirstOrDefault();
                        }
                        else
                        {
                            conflictValue = this.context.CaEventConflicts.Where(x => x.FieldName == fieldCommentUpdateModel.ConflictIdentifier
                            && x.GoldenRecordId == displayObject.CaapsId
                            && x.OptionNumber == fieldCommentUpdateModel.OptionNumber
                            && x.MovementId == fieldCommentUpdateModel.MovementNumber).FirstOrDefault();
                        }
                        if (conflictValue != null)
                        {
                            if (fieldCommentUpdateModel.ConflictIdentifier == "eventdetail.name.indicator")
                            {
                                CaEventConflict companyName = this.context.CaEventConflicts.Where(x => x.FieldName == "eventdetail.newcompanyname.narrative" && x.GoldenRecordId == displayObject.CaapsId).FirstOrDefault();
                                if (updateEventManuallyParameter.DisplayObject.NameChange.ToUpper() == "NAME")
                                {
                                    if (!String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.NewCompanyName) &&
                                        (companyName.ReviewStatus == (byte)EventReviewStatus.SystemResolved || companyName.ReviewStatus == (byte)EventReviewStatus.UserResolved))
                                    {
                                        companyName.FieldStatus = 0;
                                        companyName.ReviewStatus = 3;
                                    }
                                    else if (String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.NewCompanyName) && String.IsNullOrEmpty(companyName.ResolveValue))
                                    {
                                        companyName.FieldStatus = 2;
                                        companyName.ReviewStatus = 1;
                                        conditionalFieldChange = true;
                                    }
                                    else
                                    {
                                        companyName.FieldStatus = 0;
                                        companyName.ReviewStatus = 3;
                                    }
                                }
                                else
                                {
                                    companyName.FieldStatus = 0;
                                    companyName.ReviewStatus = 3;
                                    companyName.ResolveValue = null;
                                    companyName.ResolveType = null;
                                    companyName.ResolveBy = null;
                                    companyName.Comments = null;
                                    this.context.CaEventConflicts.Update(companyName);
                                    this.context.SaveChanges();
                                }
                                this.context.CaEventConflicts.Update(companyName);
                                this.context.SaveChanges();
                                if (conditionalFieldChange)
                                {
                                    this.UpdateWorkFlowStatus(displayObject.CaapsId, UserRoleConsts.ADMIN, UserId, conditionalFieldChange);
                                }
                            }

                            if (fieldCommentUpdateModel.ConflictIdentifier == "optiondetail.optionstatus.indicator")
                            {
                                if (updateEventManuallyParameter.DisplayObject.Options.Where(x => x.CaOptOptionNumber == conflictValue.OptionNumber).FirstOrDefault().CaOptOptionStatus == "CANC")
                                {
                                    List<CaEventConflict> allMissingConflicts = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == conflictValue.GoldenRecordId && x.OptionNumber == conflictValue.OptionNumber && (
                                    (x.FieldStatus == Convert.ToInt32(EventFieldStatus.Conflict) ||
                                    x.FieldStatus == Convert.ToInt32(EventFieldStatus.Incomplete)) &&
                                    x.ReviewStatus == Convert.ToInt32(EventReviewStatus.Open))).ToList();
                                    allMissingConflicts.ForEach(missingConflict =>
                                    {
                                        missingConflict.ResolveValue = ResolveString(missingConflict.FieldName);
                                        missingConflict.ReviewStatus = Convert.ToByte(EventReviewStatus.InReview);
                                        missingConflict.ResolveType = "CAAPS";
                                        conditionalFieldChange = true;
                                        this.context.CaEventConflicts.Update(missingConflict);
                                    });
                                }
                            }

                            if (fieldCommentUpdateModel.ConflictIdentifier == "eventdetail.informationtobecompliedwith.flag")
                            {
                                CaEventConflict informationToBeCompliedWithNarrative = this.context.CaEventConflicts.Where(x => x.FieldName == "eventtext.informationtobecompliedwith.narrative" && x.GoldenRecordId == displayObject.CaapsId).FirstOrDefault();

                                if (informationToBeCompliedWithNarrative == null)
                                {
                                    CaEventConflict caEventConflict = new CaEventConflict();
                                    caEventConflict.GoldenRecordId = displayObject.CaapsId;
                                    caEventConflict.FieldName = "eventtext.informationtobecompliedwith.narrative";
                                    caEventConflict.OptionNumber = string.Empty;
                                    caEventConflict.MovementId = string.Empty;
                                    caEventConflict.ExistingSource = conflictValue.ExistingSource;
                                    caEventConflict.ClientValue = "";
                                    caEventConflict.NewEventId = 0;
                                    caEventConflict.NewEventSource = "";
                                    caEventConflict.NewEventValue = "";
                                    caEventConflict.NewEventOptionNumber = "";
                                    caEventConflict.NewEventMovementId = "";
                                    caEventConflict.IsActive = 1;
                                    caEventConflict.EntryBy = 9990;
                                    caEventConflict.EntryDtTime = DateTime.Now;
                                    caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                                    this.context.CaEventConflicts.Add(caEventConflict);
                                    this.context.SaveChanges();
                                    informationToBeCompliedWithNarrative = this.context.CaEventConflicts.Where(x => x.FieldName == "eventtext.informationtobecompliedwith.narrative" && x.GoldenRecordId == displayObject.CaapsId).FirstOrDefault();
                                }

                                if (updateEventManuallyParameter.DisplayObject.CADtlInformationtobeCompliedWith.ToUpper() == "Y")
                                {
                                    if (!String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.AddInfoInformationtobeCompliedWith) &&
                                        (informationToBeCompliedWithNarrative.ReviewStatus == (byte)EventReviewStatus.SystemResolved || informationToBeCompliedWithNarrative.ReviewStatus == (byte)EventReviewStatus.UserResolved))
                                    {
                                        informationToBeCompliedWithNarrative.FieldStatus = 0;
                                        informationToBeCompliedWithNarrative.ReviewStatus = 3;
                                    }
                                    else if (String.IsNullOrEmpty(updateEventManuallyParameter.DisplayObject.AddInfoInformationtobeCompliedWith) && String.IsNullOrEmpty(informationToBeCompliedWithNarrative.ResolveValue))
                                    {
                                        informationToBeCompliedWithNarrative.FieldStatus = 2;
                                        informationToBeCompliedWithNarrative.ReviewStatus = 1;
                                        conditionalFieldChange = true;
                                    }
                                    else
                                    {
                                        informationToBeCompliedWithNarrative.FieldStatus = 0;
                                        informationToBeCompliedWithNarrative.ReviewStatus = 3;
                                    }
                                }
                                else
                                {
                                    informationToBeCompliedWithNarrative.FieldStatus = 0;
                                    informationToBeCompliedWithNarrative.ReviewStatus = 3;
                                    informationToBeCompliedWithNarrative.ResolveValue = null;
                                    informationToBeCompliedWithNarrative.ResolveType = null;
                                    informationToBeCompliedWithNarrative.ResolveBy = null;
                                    informationToBeCompliedWithNarrative.Comments = null;
                                    this.context.CaEventConflicts.Update(informationToBeCompliedWithNarrative);
                                    this.context.SaveChanges();
                                }
                                this.context.CaEventConflicts.Update(informationToBeCompliedWithNarrative);
                                this.context.SaveChanges();
                                if (conditionalFieldChange)
                                {
                                    this.UpdateWorkFlowStatus(displayObject.CaapsId, UserRoleConsts.ADMIN, UserId, conditionalFieldChange);
                                }
                            }

                            if (fieldCommentUpdateModel.ConflictIdentifier == "optiondetail.securityid" || fieldCommentUpdateModel.ConflictIdentifier == "optiondetail.securityidtype")
                            {
                                var optSecIdType = displayObject.Options.Where(x => x.CaOptOptionNumber == fieldCommentUpdateModel.OptionNumber).FirstOrDefault()
                                    .CaOptSecurityIDType;
                                var optSecId = displayObject.Options.Where(x => x.CaOptOptionNumber == fieldCommentUpdateModel.OptionNumber).FirstOrDefault()
                                    .CaOptSecurityID;
                                GoldenRecordSecurityDetail existingObject = this.context.GoldenRecordSecurityDetails.Where(x => x.GoldenRecordId == fieldCommentUpdateModel.GoldenRecordId
                                    && x.OptionNumber == fieldCommentUpdateModel.OptionNumber
                                    && x.MovementId == "").FirstOrDefault();

                                if (existingObject == null)
                                {
                                    existingObject = new GoldenRecordSecurityDetail();
                                    existingObject.GoldenRecordId = fieldCommentUpdateModel.GoldenRecordId;
                                    existingObject.OptionNumber = fieldCommentUpdateModel.OptionNumber;
                                    existingObject.MovementId = "";
                                    existingObject.CUSIP = optSecIdType == "CUSP" ? optSecId : "";
                                    existingObject.ISIN = optSecIdType == "ISIN" ? optSecId : "";
                                    existingObject.Sedol = optSecIdType == "Sedol" ? optSecId : "";
                                    existingObject.BloombergId = "";
                                    existingObject.ShortName = "";
                                    existingObject.LongName = "";
                                    existingObject.IsActive = 1;
                                    existingObject.EntryBy = UserId;
                                    existingObject.EntryDtTime = DateTime.Now;
                                    existingObject.EntryDtTimeUtc = DateTime.UtcNow;
                                    this.context.GoldenRecordSecurityDetails.Add(existingObject);
                                }
                                else
                                {
                                    if ((optSecIdType == "CUSP" && optSecId != existingObject.CUSIP)
                                        || (optSecIdType == "ISIN" && optSecId != existingObject.ISIN)
                                        || (optSecIdType == "Sedol" && optSecId != existingObject.Sedol)
                                        )
                                    {
                                        existingObject.CUSIP = optSecIdType == "CUSP" ? optSecId : "";
                                        existingObject.ISIN = optSecIdType == "ISIN" ? optSecId : "";
                                        existingObject.Sedol = optSecIdType == "Sedol" ? optSecId : "";
                                        existingObject.BloombergId = "";
                                        existingObject.ShortName = "";
                                        existingObject.LongName = "";
                                        this.context.GoldenRecordSecurityDetails.Update(existingObject);
                                    }
                                }
                                this.context.SaveChanges();
                            }

                            conflictValue.Comments = fieldCommentUpdateModel.Comments;
                            conflictValue.EntryBy = UserId;
                            conflictValue.EntryDtTime = DateTime.Now;
                            conflictValue.EntryDtTimeUtc = DateTime.UtcNow;
                            this.context.CaEventConflicts.Update(conflictValue);
                            Logger.Log("UpdateEventManually : !updateEventManuallyParameter.IsCloneMovement this.context.SaveChanges()", LogType.Info);
                            this.context.SaveChanges();
                        }
                        else
                        {
                            CaEventConflict caEventConflict = new CaEventConflict();
                            caEventConflict.GoldenRecordId = displayObject.CaapsId;
                            caEventConflict.FieldName = fieldCommentUpdateModel.FieldName;
                            caEventConflict.OptionNumber = fieldCommentUpdateModel.OptionNumber;
                            caEventConflict.MovementId = fieldCommentUpdateModel.MovementNumber;
                            caEventConflict.ExistingSource = fieldCommentUpdateModel.Source;
                            caEventConflict.ClientValue = "";
                            caEventConflict.NewEventId = 0;
                            caEventConflict.NewEventSource = "";
                            caEventConflict.NewEventValue = "";
                            caEventConflict.NewEventOptionNumber = "";
                            caEventConflict.NewEventMovementId = "";
                            caEventConflict.ResolveBy = null;
                            caEventConflict.ResolveType = null;
                            caEventConflict.ResolveValue = null;
                            caEventConflict.FieldStatus = 0;
                            caEventConflict.ReviewStatus = 3;
                            caEventConflict.Comments = fieldCommentUpdateModel.Comments;
                            caEventConflict.IsActive = 1;
                            caEventConflict.EntryBy = 9990;
                            caEventConflict.EntryDtTime = DateTime.Now;
                            caEventConflict.EntryDtTimeUtc = DateTime.UtcNow;
                            this.context.CaEventConflicts.Add(caEventConflict);
                            this.context.SaveChanges();
                        }
                    }
                }

                Logger.Log("UpdateEventManually : Adding clone options", LogType.Info);
                sendSolaceMessage = AddOrCloneOption(displayObject, updateEventManuallyParameter, UserId, sendSolaceMessage);
                CloneMovementConflictChanges(displayObject, updateEventManuallyParameter, UserId);

                //update Dates in golden Record master table
                Logger.Log($"UpdateEventManually : Getting GoldenRecordMsts for CaapsID : {displayObject.CaapsId}", LogType.Info);
                GoldenRecordMst g = this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == displayObject.CaapsId).FirstOrDefault();
                if (g != null)
                {
                    g.EarlyResponseDeadlineDate = flagDetails.EarlyResponseDeadline;
                    g.ProtectDate = flagDetails.ProtectDate;
                    g.ResponseDeadlineDate = flagDetails.ResponseDeadline;
                    g.MarketDeadlineDate = flagDetails.MarketDeadline;
                    g.IsAdditionalTextUpdated = flagDetails.IsAdditionTextUpdated;
                    g.IsInformationConditionsUpdated = flagDetails.IsInformationConditionsUpdated;
                    g.IsInformationToComplyUpdated = flagDetails.IsInformationToComplyUpdated;
                    g.IsNarrativeVersionUpdated = flagDetails.IsNarrativeVersionUpdated;
                    g.IsTaxationConditionsUpdated = flagDetails.IsTaxationConditionUpdated;
                    g.IsoExpiryDate = flagDetails.ISOExpiryDate;
                    g.IsoChangeType = flagDetails.ISOChangeType;
                    g.IsoEffectiveDate = flagDetails.ISOEffectiveDate;
                    g.IsoExDividendOrDistributionDate = flagDetails.ISOExDividendDate;
                    g.IsoOfferor = flagDetails.ISOOfferor;
                    g.IsoRecordDate = flagDetails.ISORecordDate;
                    g.IsTouched = true;
                    g.IsAutoStp = false;
                    g.EntryBy = UserId;
                    g.EntryDtTime = DateTime.Now;
                    g.EntryDtTimeUtc = DateTime.UtcNow;
                    if (isGPDUpdateorNot == true)
                    {
                        g.PositionFixDate = null;
                        g.IsPositionCaptured = false;
                        this.context.Database.ExecuteSqlRaw($"Exec Proc_Web_Submit_GoldenRecord_Position_Flag_Update_All_Related_Securities {displayObject.CaapsId}");
                    }

                    Logger.Log($"UpdateEventManually : Saving GoldendRecordMst: {JsonConvert.SerializeObject(g)}", LogType.Info);

                    this.context.SaveChanges();
                    this.SaveInActiveDate(g.GoldenRecordId);
                    this.SetResponseDeadlineDates((int)g.GoldenRecordId, UpdatedMessage, UserId);

                    if (sendSolaceMessage == 1)
                    {
                        ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, UpdatedMessage, g);
                        Logger.Log("UpdateEventManually :Solace Message send = " + solaceMessage.IsSuccess, LogType.Debug);
                    }
                    Logger.Log($"UpdateEventManually :Sending Event Notification for CaapsID : {displayObject.CaapsId}", LogType.Debug);
                    sendEventNotification(
                    $"Event approval perform",
                    "EVENT_APPROVAL",
                    new
                    {
                        GoldenId = displayObject.CaapsId
                    });
                }
                res.IsSuccess = true;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                res.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                res.IsSuccess = false;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                res.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = JsonConvert.SerializeObject(updateEventManuallyParameter);
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return res;
        }

        public List<EventElectionModel> GetEventElectionByElectionMappingId(long eventElectionMappingId)
        {
            List<EventElectionModel> eventElections = new List<EventElectionModel>();
            var optionNumberforAll = this.context.CaEventElectionOptionsDtls.Where(x => x.CaEventElectionMappingId == eventElectionMappingId)
                .Select(x => new
                {
                    x.OptionNumber
                }).FirstOrDefault();

            var eventElectionMappings = this.context.CaEventElectionMappings.Where(x =>
            x.CaEventElectionMappingId == eventElectionMappingId && x.IsDefault == 0 && x.IsActive == 1)
                .Select(x => new
                {
                    x.CaEventElectionId,
                    x.Mt565SemeRef
                }).ToList();

            var eventElectionMappingsAud = this.context.CaEventElectionMappingAudits.Where(x =>
            x.CaEventElectionMappingId == eventElectionMappingId && x.IsDefault == 0 && x.IsActive == 1)
                .Select(x => new
                {
                    x.CaEventElectionId,
                    x.Mt565SemeRef
                }).ToList();

            if (eventElectionMappings.Count > 0 || eventElectionMappingsAud.Count > 0)
            {

                var totalEventElection = eventElectionMappingsAud.Count > 0 ? eventElectionMappings.Union(eventElectionMappingsAud).ToList() :
                    eventElectionMappings.Count > 0 ? eventElectionMappings : null;

                eventElections = (
                    from tee in totalEventElection
                    join cee in this.context.CaEventElections on tee.CaEventElectionId equals cee.CaEventElectionId
                    select new EventElectionModel
                    {
                        EventElectionId = cee.CaEventElectionId,
                        BIC = cee.SenderBic,
                        EntryDateTimeUtc = cee.EntryDtTimeUtc,
                        OptionNumber = optionNumberforAll.OptionNumber,
                        SEMERef = tee.Mt565SemeRef,
                        SwiftMessage = cee.MessageText,
                        TradingAccountNumber = cee.TradingAccountNumber
                    }).Distinct().ToList();
            }
            return eventElections.OrderBy(x => x.EntryDateTimeUtc).ToList();

        }

        public EventDropdownResponse GetEventPageDropdownMst(int userId)
        {
            EventDropdownResponse eventDropdownResponse = new EventDropdownResponse();
            try
            {
                eventDropdownResponse.EventTypes = new List<DropdownData>();
                eventDropdownResponse.EventTypes.Add(new DropdownData
                {
                    Value = "All",
                    Name = "All"
                });

                eventDropdownResponse.EventRiskTypes = new List<DropdownData>();
                eventDropdownResponse.EventRiskTypes.Add(new DropdownData
                {
                    Value = "0",
                    Name = "All"
                });

                eventDropdownResponse.Events = new List<DropdownData>();
                eventDropdownResponse.Events.Add(new DropdownData
                {
                    Value = "All",
                    Name = "All"
                });

                eventDropdownResponse.HasPostions = new List<DropdownData>();
                eventDropdownResponse.HasPostions.Add(new DropdownData
                {
                    Value = "All",
                    Name = "All",
                });
                eventDropdownResponse.HasPostions.Add(new DropdownData
                {
                    Value = "True",
                    Name = "Yes",
                });
                eventDropdownResponse.HasPostions.Add(new DropdownData
                {
                    Value = "False",
                    Name = "No",
                });

                eventDropdownResponse.WorkQueues = new List<DropdownData>();
                eventDropdownResponse.WorkQueues.Add(new DropdownData
                {
                    Value = "All",
                    Name = "All",
                });

                eventDropdownResponse.WorkFlowStatus = new List<DropdownData>();
                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "All",
                    Name = "All",
                });
                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Complete",
                    Name = "Complete",
                });

                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Withdrawn",
                    Name = "Withdrawn",
                });

                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Cancelled",
                    Name = "Cancelled",
                });

                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Deleted",
                    Name = "Deleted",
                });

                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Conditional",
                    Name = "Conditional",
                });
                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Conflict",
                    Name = "Conflict",
                });

                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Updated",
                    Name = "Updated",
                });

                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Pending Complete",
                    Name = "Pending Complete",
                });

                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Pending Cancel",
                    Name = "Pending Cancel",
                });
                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Pending Delete",
                    Name = "Pending Delete",
                });

                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Pending Withdraw",
                    Name = "Pending Withdraw",
                });

                eventDropdownResponse.WorkFlowStatus.Add(new DropdownData
                {
                    Value = "Incomplete",
                    Name = "Incomplete",
                });

                eventDropdownResponse.CountryOfIssue = new List<DropdownData>();
                eventDropdownResponse.CountryOfIssue.Add(new DropdownData
                {
                    Value = "All",
                    Name = "All",
                });
                eventDropdownResponse.CountryOfIssue.Add(new DropdownData
                {
                    Value = "US",
                    Name = "US(United States of America)",
                });

                string fieldData = System.IO.File.ReadAllText("./EventDates.json", Encoding.UTF8);
                eventDropdownResponse.Dates = JsonConvert.DeserializeObject<List<DropdownData>>(fieldData);
                eventDropdownResponse.CibcEntity = new List<DropdownData>();
                eventDropdownResponse.CibcEntity.Add(new DropdownData
                {
                    Value = "All",
                    Name = "All",
                });
                eventDropdownResponse.ClientLegalEntity = new List<DropdownData>();

                var eventTypes = this.context.CaEventTypeMsts.Where(a => a.IsActive == 1).DistinctBy(a => a.CaEventType).ToList();
                var eventRiskTypes = this.context.CaEventRiskTypes.Where(a => a.IsActive == 1).DistinctBy(a => a.RiskTypeName).ToList();
                var eventCodes = this.context.CaEventMsts.Where(a => a.IsActive == 1).DistinctBy(a => a.CaEventCode).ToList();
                var countryOfIssues = this.context.CountryMsts.Where(a => a.IsActive == 1).DistinctBy(a => a.Alpha2).ToList();

                var cibcEntities = this.context.SenderEntityBicDtls.Where(a => a.IsActive == 1).DistinctBy(a => a.EntityShortCode).ToList();
                var clientLegalEntities = this.context.AccountMsts.Where(a => a.IsActive == 1).ToList();



                var workQueueList = new List<WorkQueueMst>();
                if (userId > 0)
                {
                    workQueueList = (from wqm in this.context.WorkQueueMsts
                                     join wqum in this.context.WorkQueueUserMappings on wqm.WorkQueueId equals wqum.WorkQueueId
                                     where ((wqm.IsActive == 1) && (wqum.UserId == userId))
                                     select wqm).ToList();
                }
                else
                {

                    workQueueList = this.context.WorkQueueMsts.Where(a => a.IsActive == 1).DistinctBy(a => a.WorkQueueName).ToList();
                }

                foreach (var coi in countryOfIssues)
                {
                    eventDropdownResponse.CountryOfIssue.Add(new DropdownData
                    {
                        Value = coi.Alpha2,
                        Name = $"{coi.Alpha2}({coi.CountryName})",
                    });
                }

                foreach (var eventType in eventTypes)
                {
                    eventDropdownResponse.EventTypes.Add(new DropdownData
                    {
                        Value = eventType.CaEventType,
                        Name = eventType.CaEventType,
                    });
                }

                foreach (var eventCode in eventCodes)
                {
                    eventDropdownResponse.Events.Add(new DropdownData
                    {
                        Value = eventCode.CaEventCode,
                        Name = eventCode.CaEventCode
                    });
                }

                foreach (var eventRiskType in eventRiskTypes)
                {
                    eventDropdownResponse.EventRiskTypes.Add(new DropdownData
                    {
                        Value = eventRiskType.CaEventRiskTypesId.ToString(),
                        Name = eventRiskType.RiskTypeName,

                    });
                }

                foreach (var workQueue in workQueueList)
                {
                    eventDropdownResponse.WorkQueues.Add(new DropdownData
                    {
                        Value = workQueue.WorkQueueName,
                        Name = workQueue.WorkQueueName
                    });
                }

                foreach (var cibcEntity in cibcEntities)
                {
                    eventDropdownResponse.CibcEntity.Add(new DropdownData
                    {
                        Value = cibcEntity.EntityShortCode,
                        Name = cibcEntity.EntityShortCode,
                    });
                }

                foreach (var clientLegalEntity in clientLegalEntities)
                {
                    eventDropdownResponse.ClientLegalEntity.Add(new DropdownData
                    {
                        Value = clientLegalEntity.LegalEntityName,
                        Name = clientLegalEntity.LegalEntityName,
                    });
                }


                eventDropdownResponse.IsSuccess = true;
                eventDropdownResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                eventDropdownResponse.MessageId = (int)ResponseCodeMessage.Successful;
                Console.WriteLine("Events");
            }
            catch (Exception ex)
            {
                eventDropdownResponse.IsSuccess = false;
                eventDropdownResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                eventDropdownResponse.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.userId = userId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);

            }
            return eventDropdownResponse;
        }

        public string GetBloombergId(int GoldenRecordId)
        {
            string bloombergId = string.Empty;
            try
            {
                var details = this.context.GoldenRecordMsts.Where(x => x.GoldenRecordId == GoldenRecordId).
                Select(x => new
                {
                    x.MatchDateName,
                    x.BloombergId
                }).FirstOrDefault();
                bloombergId = JsonConvert.SerializeObject(details);
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = GoldenRecordId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return bloombergId;
        }

        public OptionDropdownResponse GetOptionTypes(string eventName, string eventType)
        {
            OptionDropdownResponse optionDropdownResponse = new OptionDropdownResponse();
            try
            {
                List<OptionDropdownData> options = new List<OptionDropdownData>();
                options = (from caEventConfig in this.context.CaEventConfigs
                           join caEventMst in this.context.CaEventMsts on caEventConfig.CaEventMstId equals caEventMst.CaEventMstId
                           join caEventTypeMsts in this.context.CaEventTypeMsts on caEventConfig.CaEventTypeId equals caEventTypeMsts.CaEventTypeId
                           where ((caEventMst.CaEventCode.ToLower() == eventName.ToLower()) && (caEventTypeMsts.CaEventType.ToLower() == eventType.ToLower()) && (caEventConfig.IsActive == 1) && (caEventMst.IsActive == 1) && (caEventTypeMsts.IsActive == 1))
                           select new OptionDropdownData
                           {
                               EventType = caEventTypeMsts.CaEventType,
                               Event = caEventMst.CaEventCode,
                               OptionTypes = caEventConfig.SupportedOptionType
                           }).ToList();
                optionDropdownResponse.options = options;
                optionDropdownResponse.IsSuccess = true;
                optionDropdownResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                optionDropdownResponse.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                optionDropdownResponse.IsSuccess = false;
                optionDropdownResponse.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                optionDropdownResponse.MessageId = (int)ResponseCodeMessage.InternalServerError;
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return optionDropdownResponse;
        }

        public string ResendNotification(EventPublishedDetail notification)
        {
            try
            {
                if (notification.DestinationType == "Swift")
                {
                    ManualSentMsgFromSwiftProcessor obj = new ManualSentMsgFromSwiftProcessor();
                    obj.semeref = notification.SEMERef;
                    obj.Event = notification.SwiftMessage;
                    obj.goldenRecordId = notification.EventRefId;
                    obj.type = "Manual";

                    if (solaceSettings.SendToTopic)
                    {
                        this.solaceMessageListener.SendToTopic(solaceSettings.ResendNotificationTopicName, JsonConvert.SerializeObject(obj));
                    }
                    else
                    {
                        this.solaceMessageListener.SendToQueue(solaceSettings.ResendNotificationQueueName, JsonConvert.SerializeObject(obj));
                    }
                }
                else
                {
                    if (solaceSettings.SendToTopic)
                    {
                        this.solaceMessageListener.SendToTopic(solaceSettings.ResendEmailTopicName, notification.EmailMsg);
                    }
                    else
                    {
                        this.solaceMessageListener.SendToQueue(solaceSettings.ResendEmailQueueName, notification.EmailMsg);
                    }
                }

                //this.solaceMessageListener.SendToQueue("caaps_dev_arrowqueue", JsonConvert.SerializeObject(obj));
                return "{ \"status\":\"sent\" }";
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = notification.EventRefId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
                return "{ \"status\":\"not sent\" }";
            }
        }

        public ResponseParent UpdateOptionExceptionStatus(long GoldenRecordId, int UserId, bool FromAddOption = false)
        {
            ResponseParent res = new ResponseParent();
            try
            {
                CaEventConflict optionExceptionForGoldenRecord = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == GoldenRecordId && x.FieldName == "optiondetail" && x.FieldStatus == 2).FirstOrDefault();
                if (optionExceptionForGoldenRecord != null)
                {
                    optionExceptionForGoldenRecord.FieldStatus = 0;
                    optionExceptionForGoldenRecord.EntryBy = UserId;
                    optionExceptionForGoldenRecord.EntryDtTime = DateTime.Now;
                    optionExceptionForGoldenRecord.EntryDtTimeUtc = DateTime.UtcNow;
                    this.context.CaEventConflicts.Update(optionExceptionForGoldenRecord);
                    this.context.SaveChanges();

                    if (FromAddOption)
                    {
                        UserMst user = this.context.UserMsts.Where(x => x.UserId == UserId).FirstOrDefault();
                        AuditTrailOperationalDetail auditTrailDetail = new AuditTrailOperationalDetail();
                        auditTrailDetail.LogType = "DEBUG";
                        auditTrailDetail.MessageText = "{'message': 'Option Exception resolved', 'Type': 'EVENT_UPDATE'}";
                        auditTrailDetail.Comments = "Option Exception resolved";
                        auditTrailDetail.ActionCategory = "Edits & Resolution";
                        auditTrailDetail.GoldenRecordId = GoldenRecordId;
                        auditTrailDetail.OldValue = null;
                        auditTrailDetail.NewValue = null;
                        auditTrailDetail.AuditTrailOperationId = 0;
                        auditTrailDetail.EntryBy = UserId;
                        auditTrailDetail.EntryByName = user.FullName;
                        auditTrailDetail.EntryDtTime = DateTime.Now;
                        auditTrailDetail.EntryDtTimeUtc = DateTime.UtcNow;
                        auditTrailDetail.ActionType = "EDITS";
                        this.auditTrailDBHandler.AddOperationalAuditLog(auditTrailDetail);
                    }

                    this.UpdateWorkFlowStatus(GoldenRecordId, UserRoleConsts.ADMIN, UserId);
                }
                res.IsSuccess = true;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                res.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                res.IsSuccess = false;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                res.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = "Golden record id: " + GoldenRecordId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return res;
        }

        public ResponseParent ProcessUnsupportedEvents(ProcessUnsupportedEventRequestModel data, int UserId)
        {
            ResponseParent res = new ResponseParent();
            try
            {
                CaUnsupportedEventProcess caUnsupportedEventProcess = new CaUnsupportedEventProcess();
                caUnsupportedEventProcess.StartDateTime = data.StartDateTime;
                caUnsupportedEventProcess.EndDateTime = data.EndDateTime;
                caUnsupportedEventProcess.EventName = data.Event;
                caUnsupportedEventProcess.EventType = data.EventType;
                caUnsupportedEventProcess.EntryBy = UserId;
                caUnsupportedEventProcess.EntryDtTime = DateTime.Now;
                caUnsupportedEventProcess.EntryDtTimeUtc = DateTime.UtcNow;
                caUnsupportedEventProcess.IsActive = 1;
                caUnsupportedEventProcess.EventStatus = "Pending";
                caUnsupportedEventProcess.ProcessStartTime = DateTime.UtcNow;
                caUnsupportedEventProcess.ProcessEndTime = DateTime.UtcNow - new TimeSpan(0, 1, 0);

                this.context.CaUnsupportedEventProcesses.Add(caUnsupportedEventProcess);
                this.context.SaveChanges();

                //send solace message with id and other parameters
                ProcessUnsupportedMessageModel processUnsupportedMessageModel = new ProcessUnsupportedMessageModel();
                processUnsupportedMessageModel.Id = caUnsupportedEventProcess.CaUnsupportedEventProcessId;
                processUnsupportedMessageModel.EventName = caUnsupportedEventProcess.EventName;
                processUnsupportedMessageModel.EventType = caUnsupportedEventProcess.EventType;
                processUnsupportedMessageModel.StartDateTime = caUnsupportedEventProcess.StartDateTime.GetValueOrDefault();
                processUnsupportedMessageModel.EndDateTime = caUnsupportedEventProcess.EndDateTime.GetValueOrDefault();
                if (solaceSettings.SendToTopic)
                {
                    this.solaceMessageListener.SendToTopic(solaceSettings.SwiftProcessorTopicName, JsonConvert.SerializeObject(processUnsupportedMessageModel));
                }
                else
                {
                    this.solaceMessageListener.SendToQueue(solaceSettings.SwiftProcessorQueueName, JsonConvert.SerializeObject(processUnsupportedMessageModel));
                }

                res.IsSuccess = true;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                res.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                res.IsSuccess = false;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                res.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = data;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return res;
        }

        public List<CaUnsupportedEventProcess> GetProcessUnsupportedEventsData()
        {
            List<CaUnsupportedEventProcess> caUnsupportedEventProcessData = new List<CaUnsupportedEventProcess>();
            try
            {
                caUnsupportedEventProcessData = this.context.CaUnsupportedEventProcesses.Where(x => x.IsActive == 1)
                    .AsQueryable().OrderByDescending(x => x.EntryDtTimeUtc).ToList();
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return caUnsupportedEventProcessData;
        }

        public ResponseParent DeleteEvent(long GoldenRecordId, int UserId)
        {
            ResponseParent res = new ResponseParent();
            try
            {
                GoldenRecordMst g = this.context.GoldenRecordMsts.Where(gr => gr.GoldenRecordId == GoldenRecordId).FirstOrDefault();
                CaapsLinqToDB.DBModels.MT564Message message = this.linqToDbHelper.GetEventDetailsByGolderRecordId((long)GoldenRecordId);
                if (g != null)
                {
                    Logger.Log($"DeleteEvent EventWorkFlowStatus.PendingDelete", LogType.Info);
                    g.GoldenRecordStatus = EventWorkFlowStatus.PendingDelete;
                    g.EntryBy = UserId;
                    g.EntryDtTime = DateTime.Now;
                    g.EntryDtTimeUtc = DateTime.UtcNow;
                    this.context.SaveChanges();
                    ResponseParent solaceMessage = this.SendSolaceMessageLinqDB(solaceSettings.PositionCheckQueueName, message, g);
                    Logger.Log("Solace Message sending = " + solaceMessage.IsSuccess, LogType.Debug);
                    sendEventNotification(
                    $"Event Deleted",
                    "EVENT_APPROVAL",
                    new
                    {
                        GoldenId = GoldenRecordId
                    });
                }

                res.IsSuccess = true;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                res.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                res.IsSuccess = false;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                res.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = "Golden record id: " + GoldenRecordId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return res;
        }

        public List<MatchDetailsResponse> GetMatchingDetails(int goldenId)
        {
            List<MatchDetailsResponse> matchDetailsResponseList = new List<MatchDetailsResponse>();
            try
            {
                GoldenRecordMst goldenRecord = this.context.GoldenRecordMsts.Where(a => a.GoldenRecordId == goldenId).FirstOrDefault();

                List<GoldenRecordSourceEventMapping> goldenRecordSourceEventMappingList =
                    this.context.GoldenRecordSourceEventMappings.Where(a => a.GoldenRecordId == goldenId).ToList();

                foreach (var goldenRecordSourceEventMapping in goldenRecordSourceEventMappingList)
                {
                    MatchDetailsResponse matchDetailsResponse = new MatchDetailsResponse();
                    matchDetailsResponse.SourceName = this.context.ReceivedCaEventDtls.Where(x => x.ReceivedCaEventDtlId == Convert.ToInt32(goldenRecordSourceEventMapping.ReceivedId)).FirstOrDefault().FileImportMstId == -2 ? this.context.UserMsts.Where(x => x.UserId == Convert.ToInt32(goldenRecordSourceEventMapping.SourceName)).FirstOrDefault().FullName : goldenRecordSourceEventMapping.SourceName;
                    matchDetailsResponse.SourceCorpId = goldenRecordSourceEventMapping.CorpId;
                    matchDetailsResponse.SourceAdded = goldenRecordSourceEventMapping.EntryDtTimeUtc;
                    matchDetailsResponse.MatchStatus = goldenRecord.MatchStatus;
                    matchDetailsResponse.EventType = goldenRecord.EventName;
                    matchDetailsResponse.MVC = goldenRecord.EventMvc;
                    matchDetailsResponse.BloombergId = goldenRecord.BloombergId;

                    ReceivedCaEventDtl receivedCaEventDtl = this.context.ReceivedCaEventDtls.Where(a => a.ReceivedCaEventDtlId == int.Parse(goldenRecordSourceEventMapping.ReceivedId)).FirstOrDefault();
                    if (receivedCaEventDtl.NormalizedMessage != null)
                    {
                        CaapsLinqToDB.DBModels.MT564Message sourceMT564 = JsonConvert.DeserializeObject<CaapsLinqToDB.DBModels.MT564Message>(receivedCaEventDtl.NormalizedMessage);
                        DisplayData displayData = this.displayDataHelper.ToDisplayData(sourceMT564);

                        matchDetailsResponse.EffectiveDate = displayData.EffectiveDate;
                        matchDetailsResponse.MeetingDate = displayData.MeetingDate;
                        matchDetailsResponse.RecordDate = displayData.RecordDate;
                        matchDetailsResponse.PaymentDate = displayData.PaymentDate;
                        matchDetailsResponse.ExDate = displayData.ExDate;
                        matchDetailsResponse.HearingDate = displayData.HearingDate;
                        matchDetailsResponse.DeadlinetoRegister = displayData.DeadlinetoRegister;
                        matchDetailsResponse.ResultsPublicationDate = displayData.ResultsPublicationDate;
                        matchDetailsResponse.Offeror = displayData.Offeror;
                        matchDetailsResponse.CaOptMarketDeadlineDate = null;
                        matchDetailsResponse.CaOptExpiryDate = null;
                        matchDetailsResponse.CaOptProtectDate = null;

                        displayData.Options.ForEach(option =>
                        {
                            try
                            {
                                if (option.CaOptMarketDeadlineDate != null)
                                {
                                    if (matchDetailsResponse.CaOptMarketDeadlineDate == null ||
                                        DateTime.Compare(option.CaOptMarketDeadlineDate.GetValueOrDefault(), matchDetailsResponse.CaOptMarketDeadlineDate.GetValueOrDefault()) < 1)
                                    {
                                        matchDetailsResponse.CaOptMarketDeadlineDate = option.CaOptMarketDeadlineDate;
                                    }
                                }
                                if (option.CaOptExpiryDate != null)
                                {
                                    if (matchDetailsResponse.CaOptExpiryDate == null ||
                                        DateTime.Compare(option.CaOptExpiryDate.GetValueOrDefault(), matchDetailsResponse.CaOptExpiryDate.GetValueOrDefault()) < 1)
                                    {
                                        matchDetailsResponse.CaOptExpiryDate = option.CaOptExpiryDate;
                                    }
                                }
                                if (option.CaOptProtectDate != null)
                                {
                                    if (matchDetailsResponse.CaOptProtectDate == null ||
                                        DateTime.Compare(option.CaOptProtectDate.GetValueOrDefault(), matchDetailsResponse.CaOptProtectDate.GetValueOrDefault()) < 1)
                                    {
                                        matchDetailsResponse.CaOptProtectDate = option.CaOptProtectDate;
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                dynamic logs = new ExpandoObject();
                                logs.StackTrace = ex.StackTrace;
                                logs.goldenRecordId = goldenId;
                                Logger.LogException(ex, LogType.Error, logs);
                                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
                            }
                        });
                    }
                    matchDetailsResponseList.Add(matchDetailsResponse);
                }
            }
            catch (Exception ex)
            {
                Logger.LogException(ex, LogType.Error, ex.StackTrace);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, ex.StackTrace);
            }
            return matchDetailsResponseList;
        }

        public ResponseParent MatchEvent(long PrimaryGoldenRecordId, long SecondaryGoldenRecordId, int UserId)
        {
            ResponseParent res = new ResponseParent();
            try
            {
                GoldenRecordMst g = this.context.GoldenRecordMsts.Where(gr => gr.GoldenRecordId == SecondaryGoldenRecordId).FirstOrDefault();
                g.MergedRecordId = PrimaryGoldenRecordId;
                this.context.SaveChanges();

                this.DeleteEvent(SecondaryGoldenRecordId, UserId);

                res.IsSuccess = true;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                res.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                res.IsSuccess = false;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                res.MessageId = (int)ResponseCodeMessage.InternalServerError;
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = "Primary Golden record id: " + PrimaryGoldenRecordId;
                logs.Data = "Secondary Golden record id: " + SecondaryGoldenRecordId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return res;
        }

        public List<GoldenRecordResponseDeadlineDatesDtl> SetResponseDeadlineDates(int golderRecordId, CaapsLinqToDB.DBModels.MT564Message message, int EntryBy)
        {
            List<GoldenRecordResponseDeadlineDatesDtl> details = new List<GoldenRecordResponseDeadlineDatesDtl>();

            try
            {

                this.context.GoldenRecordResponseDeadlineDatesDtls.RemoveRange(this.context.GoldenRecordResponseDeadlineDatesDtls.Where(x => x.GoldenRecordId == golderRecordId));
                if (message.MessageData.CorporateActionOptions != null)
                {
                    message.MessageData.CorporateActionOptions.ToList().ForEach(option =>
                    {

                        if (option.DateTime != null)
                        {
                            option.DateTime.ToList().ForEach(dateTime =>
                            {
                                Nullable<DateTime> finalDate = null;
                                GoldenRecordResponseDeadlineDatesDtl grrDD = new GoldenRecordResponseDeadlineDatesDtl();
                                if (!String.IsNullOrEmpty(dateTime.Date))
                                {
                                    if (!String.IsNullOrEmpty(dateTime.Time))
                                    {
                                        finalDate = DateTime.ParseExact(dateTime.Date + dateTime.Time, "yyyyMMddHHmmss", CultureInfo.InvariantCulture);
                                    }
                                    else
                                    {
                                        finalDate = DateTime.ParseExact(dateTime.Date, "yyyyMMdd", CultureInfo.InvariantCulture);
                                    }
                                }

                                if (dateTime.Qualifier == "EARD")
                                {
                                    if (finalDate != null)
                                    {
                                        grrDD.DateType = "EARD";
                                        grrDD.Date = finalDate;
                                        grrDD.EntryBy = EntryBy;
                                        grrDD.GoldenRecordId = golderRecordId;
                                        grrDD.IsActive = 1;
                                        grrDD.EntryDtTime = DateTime.Now;
                                        grrDD.EntryDtTimeUtc = DateTime.UtcNow;

                                        this.context.GoldenRecordResponseDeadlineDatesDtls.Add(grrDD);
                                    }

                                }
                                else if (dateTime.Qualifier == "RDDT")
                                {
                                    if (finalDate != null)
                                    {
                                        grrDD.DateType = "RDDT";
                                        grrDD.Date = finalDate;
                                        grrDD.EntryBy = EntryBy;
                                        grrDD.GoldenRecordId = golderRecordId;
                                        grrDD.IsActive = 1;
                                        grrDD.EntryDtTime = DateTime.Now;
                                        grrDD.EntryDtTimeUtc = DateTime.UtcNow;

                                        this.context.GoldenRecordResponseDeadlineDatesDtls.Add(grrDD);
                                    }
                                }
                                details.Add(grrDD);
                            });


                            this.context.SaveChanges();

                        }

                    });
                }

            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = "Golden record id: " + golderRecordId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }

            return details;

        }

        public Boolean setGPDDate(CaapsLinqToDB.DBModels.MT564Message message, CaapsLinqToDB.DBModels.MT564Message updateMessage, string eventName, string eventType)
        {
            List<OptionDropdownData> options = new List<OptionDropdownData>();
            options = (
                from grm in this.context.GoldenRecordMsts
                join gpd in this.context.CaEventGpdConfigs on grm.GpdDateType equals gpd.GpdDateType
                where grm.GoldenRecordId == message.GoldenRecordID
                //from caEventConfig in this.context.CaEventConfigs
                //       join caEventMst in this.context.CaEventMsts on caEventConfig.CaEventMstId equals caEventMst.CaEventMstId
                //       join caEventTypeMsts in this.context.CaEventTypeMsts on caEventConfig.CaEventTypeId equals caEventTypeMsts.CaEventTypeId
                //       where ((caEventMst.CaEventCode.ToLower() == eventName.ToLower()) && (caEventTypeMsts.CaEventType.ToLower() == eventType.ToLower()) && (caEventConfig.IsActive == 1) && (caEventMst.IsActive == 1) && (caEventTypeMsts.IsActive == 1))
                select new OptionDropdownData
                {
                    //EventType = caEventTypeMsts.CaEventType,
                    //Event = caEventMst.CaEventCode,
                    //OptionTypes = caEventConfig.SupportedOptionType,
                    //GpdDate = caEventConfig.GpdDate,
                    GpdDateType = grm.GpdDateType,
                    GpdOffset = gpd.GpdOffset,

                }).ToList();

            if (options.Count > 0)
            {
                OptionDropdownData data = options.First();
                DateTime? oldDate = this.linqToDbHelper.findGPDDate(message, data.GpdDateType);
                DateTime? newDate = this.linqToDbHelper.findGPDDate(updateMessage, data.GpdDateType);
                DateTime CurrentDate = DateTime.Now;
                DateTime CompareDate = DateTime.Now;
                CompareDate.AddDays((double)data.GpdOffset);

                //if (oldDate != null && DateTime.Compare((DateTime)oldDate, CompareDate) < 0)
                //{
                if (newDate != null && DateTime.Compare((DateTime)newDate, CurrentDate) >= 0)
                {
                    return true;
                }
                //}
            }

            return false;

        }

        public ResponseParent UpdateOptionException(CaOptionException objOptionException)
        {
            ResponseParent res = new ResponseParent();
            CaOptionException optionException = new CaOptionException();
            try
            {
                if (objOptionException.CaOptionExceptionId != 0)
                {
                    optionException = this.context.CaOptionExceptions.Where(x => x.CaOptionExceptionId == objOptionException.CaOptionExceptionId).FirstOrDefault();
                }
                else
                {
                    optionException = this.context.CaOptionExceptions.Where(x => x.GoldenRecordId == objOptionException.GoldenRecordId
                    && x.MovementId == objOptionException.MovementId
                    && x.OptionNumber == objOptionException.OptionNumber
                    && x.SourceName == objOptionException.SourceName
                    && x.ExceptionStatus == "Open"
                    ).FirstOrDefault();
                }
                if (optionException != null)
                {
                    optionException.ExceptionStatus = "User Resolved";
                    this.context.SaveChanges();
                }
                res.IsSuccess = true;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.Successful);
                res.MessageId = (int)ResponseCodeMessage.Successful;
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = objOptionException.GoldenRecordId;
                Logger.LogException(ex, LogType.Error, logs);
                res.IsSuccess = false;
                res.Message = this.enumHelper.GetEnumDescription(ResponseCodeMessage.InternalServerError);
                res.MessageId = (int)ResponseCodeMessage.InternalServerError;
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            sendEventNotification(
                    $"Option Exception Ignored",
                    "LINK_OPTION",
                     new
                     {
                         GoldenId = objOptionException.GoldenRecordId
                     });
            return res;
        }

        public string LinkedClientOptionFromSourceOption(string SourceName, string SourceOptionNumber, int GoldenRecordId)
        {
            string ClientOptionNumber = null;
            try
            {
                var details = this.context.CaOptionLinks.Where(x => x.SourceName == SourceName && x.SourceOptionNumber == SourceOptionNumber
                && x.ClientLinkStatus == "Linked" && x.SourceLinkStatus == "Linked" && x.GoldenRecordId == GoldenRecordId).Select(x => new
                {
                    x.ClientOptionNumber
                }).FirstOrDefault();

                ClientOptionNumber = JsonConvert.SerializeObject(details);
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.Data = "Golden record id: " + GoldenRecordId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
            }
            return ClientOptionNumber;
        }

        public List<SourceConfig> GetSourceConfigData()
        {
            List<SourceConfig> objSourceConfig = new List<SourceConfig>();
            try
            {
                objSourceConfig = this.context.SourceConfigs.Where(x => x.IsActive == 1).ToList();
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                Logger.LogException(ex, LogType.Error, logs);
            }
            return objSourceConfig;
        }
        /* This function performs the following tasks under cr#20:
            1) using the offset_config value of respective source of particular event transforms the deadline dates.
                offset_config generally contains the array of conditions in json format. each array contains the certain fields 
                which define the behaviour or requirement of that particular condition.
            2) if the rddt is derived value than derived_offset_will be used provided by source itself.
         */
        public DateTime GetConvertedDateTimeByTimeZone(string date, string sourceName, string LOB, bool isREDMConditional)
        {
            DateTime clientDateTime = Convert.ToDateTime(date);

            if(isREDMConditional || configuration["ApplicationSettings:NewRDDTCalculation"].ToLower() == "true")
            {
                SourceConfig objSourceConfig = this.context.SourceConfigs.FirstOrDefault(x => x.SourceName == sourceName &&
                x.LOB == ((LOB == "null" || LOB == string.Empty || LOB == null) ? null : LOB));
                if (objSourceConfig != null)
                {
                    string strOffsetConfig = isREDMConditional ? objSourceConfig.DerivedOffsetConfig : objSourceConfig.OffsetConfig;
                    OffsetConfigModel objOffsetConfig = JsonConvert.DeserializeObject<OffsetConfigModel>(strOffsetConfig);

                    for (int i = 0; i < objOffsetConfig.Condition.Count; i++)
                    {
                        OffsetConfigFormat objCondition = objOffsetConfig.Condition[i];
                        if ((objCondition.RelationalOperator == "GREATERTHANEQUALTO" && clientDateTime.TimeOfDay >= Convert.ToDateTime(objCondition.CheckValueTime).TimeOfDay)
                            || (objCondition.RelationalOperator == "LESSTHAN" && clientDateTime.TimeOfDay < Convert.ToDateTime(objCondition.CheckValueTime).TimeOfDay))
                        {
                                if(objCondition.OffsetHours != null)
                                {
                                    clientDateTime = clientDateTime.AddHours(Convert.ToDouble(objCondition.OffsetHours));
                                }
                                else
                                {
                                    clientDateTime = clientDateTime.Date + Convert.ToDateTime(objCondition.SetValue).TimeOfDay;
                                }
                                if (objCondition.TimeValueNoLaterThan != null && clientDateTime.TimeOfDay >= Convert.ToDateTime(objCondition.TimeValueNoLaterThan).TimeOfDay)
                                {
                                    clientDateTime = clientDateTime.Date + Convert.ToDateTime(objCondition.TimeValueNoLaterThan).TimeOfDay;
                                }
                                clientDateTime = clientDateTime.AddDays(Convert.ToDouble(objCondition.DateOffset));
                                break;
                        }                         
                    }

                    while (this.context.HolidayMsts.Where(x => x.HolidayDate.Date == clientDateTime.Date).Any() ||
                        clientDateTime.DayOfWeek == DayOfWeek.Saturday ||
                       clientDateTime.DayOfWeek == DayOfWeek.Sunday)
                    {
                        clientDateTime = clientDateTime.AddDays(-1);
                    }
                }
            }            
            else
            {
                string sourceTimeZone = this.context.SourceConfigs.FirstOrDefault(x => x.SourceName == sourceName).TimeZone;
                string clientTimeZone = this.context.SourceConfigs.FirstOrDefault(x => x.SourceName == "Client").TimeZone;
                double offsetHours = this.context.SourceConfigs.FirstOrDefault(x => x.SourceName == sourceName).OffsetHours;                

                if (clientDateTime.TimeOfDay == TimeSpan.Zero)
                {
                    clientDateTime = clientDateTime.AddHours(15);
                }

                if (sourceTimeZone != clientTimeZone)
                {
                    TimeZoneInfo sourceTZ = TimeZoneInfo.FindSystemTimeZoneById(sourceTimeZone);
                    DateTime sourceUTCDateTime = TimeZoneInfo.ConvertTimeToUtc(Convert.ToDateTime(date), sourceTZ);

                    TimeZoneInfo clientTZ = TimeZoneInfo.FindSystemTimeZoneById(clientTimeZone);
                    clientDateTime = TimeZoneInfo.ConvertTimeFromUtc(sourceUTCDateTime, clientTZ);
                }

                clientDateTime = clientDateTime.AddHours(offsetHours);

                while (this.context.HolidayMsts.Where(x => x.HolidayDate.Date == clientDateTime.Date).Any() ||
                    clientDateTime.DayOfWeek == DayOfWeek.Saturday ||
                   clientDateTime.DayOfWeek == DayOfWeek.Sunday)
                {
                    clientDateTime = clientDateTime.AddDays(-1);
                }
            }
            return clientDateTime;
        }

        public List<CaEventConflict> AddUpdateEventConflict(CaEventConflict conflictObject, string fieldname, int userId, bool isMissing, bool isUpdate)
        {
            //this.context.CaEventConflicts.Add(conflictObject);
            //this.context.SaveChanges();
            //if (!isMissing)
            //{
            //DisplayData displayData = this.linqToDbHelper.GetDisplayDataByGoldenRecordId((int)conflictObject.GoldenRecordId);
            //displayData.Options.ForEach(option =>
            //{
            //    if (option.CaOptOptionNumber == conflictObject.OptionNumber)
            //    {
            //        if (conflictObject.MovementId.Contains("CC") || conflictObject.MovementId.Contains("CD"))
            //        {
            //            option.cashMovements.ForEach(movement =>
            //            {
            //                if (movement.CMCashNumber == conflictObject.MovementId)
            //                {
            //                    movement.GetType().GetProperty(fieldname).SetValue(movement, conflictObject.ClientValue);
            //                }
            //            });
            //        }
            //        else if (conflictObject.MovementId.Contains("SC") || conflictObject.MovementId.Contains("SD"))
            //        {
            //            option.securityMovement.ForEach(movement =>
            //            {
            //                if (movement.SMSecurityNumber == conflictObject.MovementId)
            //                {
            //                    movement.GetType().GetProperty(fieldname).SetValue(movement, conflictObject.ClientValue);
            //                }
            //            });
            //        }
            //    }
            //});
            //}
            CaEventConflict existingObject = this.context.CaEventConflicts.Where(x => x.OptionNumber == conflictObject.OptionNumber
            && x.MovementId == conflictObject.MovementId
            && x.FieldName == conflictObject.FieldName).FirstOrDefault();
            if (existingObject != null)
            {
                existingObject.FieldStatus = conflictObject.FieldStatus;
                existingObject.ReviewStatus = conflictObject.ReviewStatus;
            }

            if (existingObject != null)
            {
                this.context.CaEventConflicts.Update(existingObject);
            }
            else
            {
                conflictObject.ClientValue = "";
                conflictObject.NewEventId = 0;
                conflictObject.NewEventSource = "";
                conflictObject.NewEventValue = "";
                conflictObject.NewEventOptionNumber = "";
                conflictObject.NewEventMovementId = "";
                conflictObject.IsActive = 1;
                conflictObject.EntryDtTime = DateTime.Now;
                conflictObject.EntryDtTimeUtc = DateTime.UtcNow;
                this.context.CaEventConflicts.Add(conflictObject);
            }

            this.context.SaveChanges();
            //this.linqToDbHelper.UpdateMT564Message(displayData);
            this.UpdateWorkFlowStatus(conflictObject.GoldenRecordId, UserRoleConsts.ADMIN, isUpdate ? Convert.ToInt32(conflictObject.ResolveBy) : conflictObject.EntryBy, true);
            List<CaEventConflict> allConflicts = this.context.CaEventConflicts.Where(x => x.GoldenRecordId == conflictObject.GoldenRecordId).ToList();
            return allConflicts;
        }

        public AMHAcknowledgement GetAcknowledgeMessage(int goldenRecordId, string semeRef)
        {
            AMHAcknowledgement objAMHAcknowledgements = new AMHAcknowledgement();
            try
            {
                objAMHAcknowledgements = this.context.AMHAcknowledgements.Where(x => x.IsActive == 1 && x.GoldenRecordId == goldenRecordId && x.SemeRef == semeRef).FirstOrDefault();
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                Logger.LogException(ex, LogType.Error, logs);
            }
            return objAMHAcknowledgements;
        }

        public string EditIgnoreNotification(EventPublishedDetail notification)
        {
            try
            {
                EditIgnoreSwiftMsg obj = new EditIgnoreSwiftMsg();
                obj.SemeRef = notification.SEMERef;
                obj.EventMsg = notification.SwiftMessage;
                obj.GoldenRecordId = Convert.ToInt32(notification.EventRefId);
                obj.MessageAction = notification.MessageAction;
                obj.LegalEntityCdrId = notification.LegalEntityCdrId;
                obj.MessageType = notification.MessageType;

                if (solaceSettings.SendToTopic)
                {
                    this.solaceMessageListener.SendToTopic(solaceSettings.EditIgnoreNotificationTopicName, JsonConvert.SerializeObject(obj));
                }
                else
                {
                    this.solaceMessageListener.SendToQueue(solaceSettings.EditIgnoreNotificationQueueName, JsonConvert.SerializeObject(obj));
                }
                return "{ \"status\":\"sent\" }";
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                logs.goldenRecordId = notification.EventRefId;
                Logger.LogException(ex, LogType.Error, logs);
                this.appNotificationSender.sendDbFailureNotification(ex.Message, logs);
                return "{ \"status\":\"not sent\" }";
            }
        }

        public List<CaEventEventTypeMapping> GetEventsAndEventTypes()
        {
            List<CaEventEventTypeMapping> objEventEventTypes = new List<CaEventEventTypeMapping>();
            try
            {
                objEventEventTypes = (from cae in this.context.CaEventEventTypeMappings
                                      join cam in this.context.CaEventMsts on cae.CaEventMstId equals cam.CaEventMstId
                                      where cae.IsActive == 1
                                      orderby cae.CaEventCode
                                      select new CaEventEventTypeMapping
                                      {
                                          CaEventCode = cae.CaEventCode,
                                          IsActive = cae.IsActive,
                                          CaEventEventTypeMappingId = cae.CaEventEventTypeMappingId,
                                          CaEventMstId = cae.CaEventMstId,
                                          CaEventType = cae.CaEventType,
                                          CaEventTypeId = cae.CaEventTypeId,
                                          EntryBy = cae.EntryBy,
                                          EntryDtTime = cae.EntryDtTime,
                                          EntryDtTimeUtc = cae.EntryDtTimeUtc,
                                          CaEventShortDescription = cam.CaEventShortDescription
                                      }
                                      ).ToList();
                //.DistinctBy(x=>x.CaEventCode).ToList();
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                Logger.LogException(ex, LogType.Error, logs);
            }
            return objEventEventTypes;
        }

        public List<ClientSecurityMst> CheckSecuritiesFromTypeandId(string securityType, string securityId)
        {
            List<ClientSecurityMst> objClientSecs = new List<ClientSecurityMst>();
            objClientSecs = (from cscr in this.context.ClientSecurityCrossReferences
                             join csm in this.context.ClientSecurityMsts on cscr.InternalSecurityId equals csm.InternalSecurityId
                             join cscr1 in this.context.ClientSecurityCrossReferences on csm.InternalSecurityId equals cscr1.InternalSecurityId
                             where cscr1.SecurityId == securityId && (cscr.SecurityIdType == "ISIN" || cscr.SecurityIdType == "CUSIP" || cscr.SecurityIdType == "SEDOL")
                             select new ClientSecurityMst
                             {
                                 InternalSecurityId = csm.InternalSecurityId,
                                 RequestId = csm.RequestId,
                                 RequestDateTime = csm.RequestDateTime,
                                 CibcInternalId = csm.CibcInternalId,
                                 AssetClass = csm.AssetClass,
                                 AssetSubClass = csm.AssetSubClass,
                                 VersionNumber = csm.VersionNumber,
                                 IssuerName = csm.IssuerName,
                                 ParAmount = csm.ParAmount,
                                 PrimaryExchangeCode = csm.PrimaryExchangeCode,
                                 PrimaryExchangeCodeMic = csm.PrimaryExchangeCodeMic,
                                 SecurityType = csm.SecurityType,
                                 ShortName = csm.ShortName,
                                 LongName = csm.LongName,
                                 LocalCurrency = csm.LocalCurrency,
                                 EquityCurrency = csm.EquityCurrency,
                                 Ticker = csm.Ticker,
                                 CountryOfIssue = csm.CountryOfIssue,
                                 CountryOfDomicile = csm.CountryOfDomicile,
                                 CountryOfRisk = csm.CountryOfRisk,
                                 CountryOfIncorporation = csm.CountryOfIncorporation,
                                 ExchangeCode = csm.ExchangeCode,
                                 IsActive = csm.IsActive,
                                 EntryBy = csm.EntryBy,
                                 EntryDtTime = csm.EntryDtTime,
                                 EntryDtTimeUtc = csm.EntryDtTimeUtc,
                                 FeedName = csm.FeedName,
                                 SecurityIdType = cscr.SecurityIdType,
                                 SecurityId = cscr.SecurityId
                             }).ToList();
            return objClientSecs;
        }

        public void SaveNewEvents(ManualEvent manualEvent)
        {
            try
            {
                Logger.Log("Manual Event : " + JsonConvert.SerializeObject(manualEvent), LogType.Info);
                MT564Message mT564Message = new MT564Message();
                mT564Message.MessageData = new CAAPS.Swift.MT564.MessageData();
                MGeneralInformation generalInformation = new MGeneralInformation();
                List<MIndicator> eventIndicators = new List<MIndicator>();
                MIndicator eventTypeIndicator = new MIndicator();
                eventTypeIndicator.PrimaryId = 0;
                eventTypeIndicator.Qualifier = "CAEV";
                eventTypeIndicator.Indicator = manualEvent.EventType;
                eventIndicators.Add(eventTypeIndicator);

                MIndicator eventMVCIndicator = new MIndicator();
                eventMVCIndicator.PrimaryId = 0;
                eventMVCIndicator.Qualifier = "CAMV";
                eventMVCIndicator.Indicator = manualEvent.MVC;
                eventIndicators.Add(eventMVCIndicator);

                generalInformation.Indicator = eventIndicators;
                mT564Message.MessageData.GeneralInformation = generalInformation;

                MFinancialInstrument instrument = new MFinancialInstrument();
                instrument.SecurityType = manualEvent.SecurityType;
                instrument.SecurityValue = manualEvent.SecurityId;
                MUnderlyingSecurities mUnderlyingSecurities = new MUnderlyingSecurities();
                mUnderlyingSecurities.FinancialInstrument = instrument;
                mT564Message.MessageData.UnderlyingSecurities = mUnderlyingSecurities;

                mT564Message.MessageData.CorporateActionDetails = new MCorporateActionDetails();
                mT564Message.MessageData.CorporateActionOptions = new List<MCorporateActionOption>();

                MatchingMessageModel matchingMessageModel = new MatchingMessageModel();
                matchingMessageModel.Message = JsonConvert.SerializeObject(mT564Message);
                matchingMessageModel.ReceivedId = -1;
                matchingMessageModel.COI = manualEvent.COI;
                matchingMessageModel.BBGID = manualEvent.BBGID;
                matchingMessageModel.InternalID = manualEvent.InternalSecurityId;
                matchingMessageModel.MessageType = "MT564";
                matchingMessageModel.FileId = -1;
                matchingMessageModel.MessageFrom = Notification.Component.WEB_SERVER;
                matchingMessageModel.MessageAction = "MANUAL_EVENT";
                matchingMessageModel.Source = "MANUAL";
                matchingMessageModel.Guid = manualEvent.EventRequestId;
                matchingMessageModel.AdditionalInfo = manualEvent.AdditionalInfo;
                matchingMessageModel.UserId = manualEvent.UserId;

                if (solaceSettings.SendToTopic)
                {
                    this.solaceMessageListener.SendToTopic(solaceSettings.MatchingTopicName, JsonConvert.SerializeObject(matchingMessageModel));
                }
                else
                {
                    this.solaceMessageListener.SendToQueue(solaceSettings.MatchingQueueName, JsonConvert.SerializeObject(matchingMessageModel));
                }
            }
            catch (Exception ex)
            {
                dynamic logs = new ExpandoObject();
                logs.StackTrace = ex.StackTrace;
                Logger.LogException(ex, LogType.Error, logs);
            }
        }

        private static bool IsConditional(GoldenRecordMst g)
        {
            bool isConditional = false;
            if ((g.EventName == "BIDS" && g.EventMvc == "VOLU")
                || (g.EventName == "DTCH" && g.EventMvc == "VOLU")
                || (g.EventName == "EXRI" && g.EventMvc == "VOLU")
                || (g.EventName == "EXRI" && g.EventMvc == "CHOS")
                || (g.EventName == "MRGR" && g.EventMvc == "CHOS")
                || (g.EventName == "TEND" && g.EventMvc == "VOLU")
                || (g.EventName == "EXOF" && g.EventMvc == "VOLU")
                || (g.EventName == "EXOF" && g.EventMvc == "CHOS")
                || (g.EventName == "OTHR" && g.EventMvc == "VOLU")
                || (g.EventName == "PRIO" && g.EventMvc == "VOLU"))
            {
                isConditional = true;
            }
            return isConditional;
        }

        private static bool IsDebitRequired(DisplayData d)
        {
            if ((d.EventName == "EXOF" && d.EventMvc == "MAND")
                || (d.EventName == "EXOF" && d.EventMvc == "CHOS")
                || (d.EventName == "EXOF" && d.EventMvc == "VOLU")
                || (d.EventName == "ODLT" && d.EventMvc == "VOLU"))
            {
                return true;
            }
            return false;
        }

        private static string ResolveString(string fieldName)
        {
            string finalString = string.Empty;
            switch (fieldName)
            {
                case "optiondetail.periodofaction.fromdatetime":
                    finalString = "{\"fromdatecode\":\"UKWN\",\"qualifier\":\"PWAL\"}";
                    break;
                case "optiondetail.periodofaction.todatetime":
                    finalString = "{\"ToDateCode\":\"UKWN\",\"qualifier\":\"PWAL\"}";
                    break;
                case "optiondetail.marketdeadlinedate.cadatetime":
                    finalString = "{\"datecode\":\"UKWN\",\"qualifier\":\"MKDT\"}";
                    break;
                case "optiondetail.responsedeadlinedate.cadatetime":
                    finalString = "{\"datecode\":\"UKWN\",\"qualifier\":\"RDDT\"}";
                    break;
                case "securitymovement.paymentdate.cadatetime":
                    finalString = "{\"datecode\":\"UKWN\",\"qualifier\":\"PAYD\"}";
                    break;
                case "cashmovement.earliestpaymentdate.cadatetime":
                    finalString = "{\"datecode\":\"UKWN\",\"qualifier\":\"EARL\"}";
                    break;
                case "cashmovement.paymentdate.cadatetime":
                    finalString = "{\"datecode\":\"UKWN\",\"qualifier\":\"PAYD\"}";
                    break;
                case "optiondetail.expirydate.cadatetime":
                    finalString = "{\"datecode\":\"UKWN\",\"qualifier\":\"EXPI\"}";
                    break;
                case "optiondetail.maximumexercisablequantity.quantity":
                    finalString = "{\"qtycode\":\"UKWN\",\"qualifier\":\"MAEX\"}";
                    break;
                case "optiondetail.minimumexercisablequantity.quantity":
                    finalString = "{\"qtycode\":\"UKWN\",\"qualifier\":\"MIEX\"}";
                    break;
                case "cashmovement.genericcashpricereceived":
                    finalString = "{\"pricecode\":\"UKWN\",\"qualifier\":\"OFFR\"}";
                    break;
                case "cashmovement.genericcashpricepaid":
                    finalString = "{\"pricecode\":\"UKWN\",\"qualifier\":\"PRPP\"}";
                    break;
                case "cashmovementrate.interestrate":
                    finalString = "{\"ratetypecode\":\"UKWN\",\"qualifier\":\"INTP\"}";
                    break;
                case "optiondetail.bidintervalrate":
                    finalString = "{\"ratetypecode\":\"UKWN\",\"qualifier\":\"BIDI\"}";
                    break;
                case "optiondetail.withdrawalallowed.flag":
                    finalString = "{\"flag\":\"N\",\"qualifier\":\"WTHD\"}";
                    break;
                case "optiondetail.narrativeversion.narrative":
                    finalString = "{\"narrative\":\"None\",\"qualifier\":\"ADTX\"}";
                    break;
                case "securitymovement.newsecurityid":
                    finalString = "{\"securityid\":\"1\"}";
                    break;
                case "securitymovement.newsecurityidtype":
                    finalString = "{\"securityidtype\":\"CUSP\"}";
                    break;
                case "securitymovement.securityrate":
                    finalString = "{\"ratetypecode\":\"UKWN\",\"qualifier\":\"ADEX\"}";
                    break;
                case "optiondetail.revocabilityperiod.fromdatetime":
                    finalString = "{\"fromdatecode\":\"UKWN\",\"qualifier\":\"REVO\"}";
                    break;
                case "optiondetail.revocabilityperiod.todatetime":
                    finalString = "{\"ToDateCode\":\"UKWN\",\"qualifier\":\"REVO\"}";
                    break;
                case "optiondetail.coverexpirationdate.cadatetime":
                    finalString = "{\"datecode\":\"UKWN\",\"qualifier\":\"CVPR\"}";
                    break;
                case "optiondetail.depositorycoverexpirationdate.cadatetime":
                    finalString = "{\"datecode\":\"UKWN\",\"qualifier\":\"DVCP\"}";
                    break;
                case "cashmovementrate.grossdividendrate":
                    finalString = "{\"ratetypecode\":\"UKWN\",\"qualifier\":\"GRSS\"}";
                    break;
                case "cashmovementrate.netdividendrate":
                    finalString = "{\"ratetypecode\":\"UKWN\",\"qualifier\":\"NETT\"}";
                    break;
                default:
                    break;
            }
            return finalString;
        }

        private static bool IsPeriodField(string fieldName)
        {
            if (fieldName == "optiondetail.revocabilityperiod.fromdatetime"
                || fieldName == "optiondetail.revocabilityperiod.todatetime"
                || fieldName == "eventdetail.claimperiod.fromdatetime"
                || fieldName == "eventdetail.claimperiod.todatetime"
                || fieldName == "optiondetail.periodofaction.fromdatetime"
                || fieldName == "optiondetail.periodofaction.todatetime")
            {
                return true;
            }
            return false;
        }

        public CheckMsgStatus CheckMsgStatus(long lGlodenID, string accountID, string msgType)
        {
            CheckMsgStatus response = new CheckMsgStatus();
            Logger.Log($"Reached inside  GetEventMsgStatus", LogType.Info);
            try
            {
                using (var scope = new System.Transactions.TransactionScope
                   (
                       System.Transactions.TransactionScopeOption.Required,
                       new System.Transactions.TransactionOptions()
                       {
                           IsolationLevel = System.Transactions.IsolationLevel.ReadUncommitted
                       }
                   )
                )
                {
                    AccountMst acc_mst = null;  //*** fetch accountId;
                    acc_mst = this.context.AccountMsts
                        .Where(acc_mst => acc_mst.TradingAccountNumber == accountID && acc_mst.IsActive == 1)
                        .FirstOrDefault();
                    string msgRes = null;
                    if (acc_mst != null)
                        {
                        // Under CR#112, a new email flow at the group level has been introduced.
                        // To ensure the existing email flow in each module remains unaffected,
                        // a check for (OMS.IsAccountGroup == 0) has been added.
                        var queryRes = (from OMS in this.context.OutboundMsts
                                     join OAM in this.context.OutBoundAccountMappings on OMS.OutboundId equals OAM.OutboundId
                                     join SOM in this.context.OutboundSwiftRefMsts on OMS.DestinationRefId equals SOM.OutboundSwiftRefId
                                     where OMS.GoldenRecordId == lGlodenID && OAM.AccountId == acc_mst.AccountId && SOM.MsgType == msgType
                                     && OMS.Destination == "Swift"
                                     && OMS.IsActive == 1 && OAM.IsActive == 1 && SOM.IsActive == 1 && OMS.IsAccountGroup == 0
                                     orderby SOM.EntryDtTime descending
                                     select new
                                     {
                                         SOM.SemeRef,
                                     }).FirstOrDefault();
                        if (queryRes != null)
                        {

                            Logger.Log($" Inside GetEventMsgStatus Message is sent via swift ", LogType.Info);
                            msgRes = queryRes.SemeRef;
                            response.IsSuccess = true;
                            response.Message = "From (Swift) :" + msgRes;
                            response.Status = true;
                            return response;
                        }
                        
                    }
                    if(msgRes == null)
                    { 
                        if (acc_mst != null)
                        {
                            // Under CR#112, a new email flow at the group level has been introduced.
                            // To ensure the existing email flow in each module remains unaffected,
                            // a check for (OMS.IsAccountGroup == 0) has been added.
                            var queryRes = (from OMS in this.context.OutboundMsts
                                     join OAM in this.context.OutBoundAccountMappings on OMS.OutboundId equals OAM.OutboundId
                                     join SOM in this.context.OutboundEmailRefMsts on OMS.DestinationRefId equals SOM.OutboundEmailRefId
                                     where OMS.GoldenRecordId == lGlodenID && OAM.AccountId == acc_mst.AccountId && SOM.MsgType == msgType
                                     && OMS.Destination == "Email"
                                     && OMS.IsActive == 1 && OAM.IsActive == 1 && SOM.IsActive == 1 && OMS.IsAccountGroup == 0
                                     orderby SOM.EntryDtTime descending
                                     select new
                                     {
                                         SOM.SemeRef,
                                     }).FirstOrDefault();
                            if (queryRes != null)
                            {
                                Logger.Log($" Inside GetEventMsgStatus Message is sent via Email ", LogType.Info);
                                msgRes = queryRes.SemeRef;
                                response.IsSuccess = true;
                                response.Message = "From (Email) :" + msgRes;
                                response.Status = true;
                                return response;
                            }
                        }
                    }
                    response.IsSuccess = true;
                    response.Message = "Value not found!";
                    response.Status = false;
                    return response;
                }
            }
            catch (Exception e)
            {
                Logger.Log($"getPrevMsgSEME566 Exception: e", LogType.Error);
                response.IsSuccess = false;
                response.Message = "The Error message is :" + e.Message;
                response.Status = false;
                return response;
            }
        }

        public CaEventConfig GetEventConfig(string eventName, string eventMVC)
        {
            CaEventConfig eventConfig = null;

            try
            {
                eventConfig = (from config in this.context.CaEventConfigs
                               join eventMst in this.context.CaEventMsts on config.CaEventMstId equals eventMst.CaEventMstId
                               join eventTypeMst in this.context.CaEventTypeMsts on config.CaEventTypeId equals eventTypeMst.CaEventTypeId
                               where eventMst.CaEventCode == eventName
                               where eventTypeMst.CaEventType == eventMVC
                               where config.IsActive == 1
                               select config as CaEventConfig).FirstOrDefault();
            }
            catch (Exception ex)
            {
                Logger.Log(ex.Message, LogType.Error);
            }

            return eventConfig;
        }

        public CaOptionTypeConfig GetOptionTypeConfig(string OptionType)
        {
            CaOptionTypeConfig optionTypeConfig = null;
            try
            {
                optionTypeConfig = (from config in this.context.CaOptionTypeConfigs
                                    where config.CaOptionType == OptionType
                                    select config as CaOptionTypeConfig
                                    ).FirstOrDefault();

            }
            catch (Exception ex)
            {
                Logger.Log(ex.Message, LogType.Error);
            }
            return optionTypeConfig;
        }
    }
}
