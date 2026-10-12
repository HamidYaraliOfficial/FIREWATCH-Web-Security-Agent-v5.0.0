from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel,Field,HttpUrl,ConfigDict,field_validator,model_validator
from .models import ScanStatus,Severity,FindingStatus
class ScanCreate(BaseModel):
    target_url:HttpUrl; scope_acknowledged:bool=False; project_id:str|None=None
    profile:str=Field('standard',pattern='^(baseline|standard|comprehensive)$')
    max_pages:int=Field(300,ge=1,le=5000); max_depth:int=Field(8,ge=0,le=20); max_endpoints:int=Field(2000,ge=10,le=10000)
    request_delay_ms:int=Field(150,ge=0,le=10000); max_concurrency:int=Field(6,ge=1,le=20)
    enable_browser:bool=True; enable_api_introspection:bool=True; enable_zap:bool=False; enable_safe_parameter_probes:bool=True; passive_only:bool=False; respect_robots:bool=True
    exclusions:list[str]=Field(default_factory=list,max_length=200); allowed_hosts:list[str]=Field(default_factory=list,max_length=20)
    request_headers:dict[str,str]=Field(default_factory=dict); auth_cookies:str|None=None; authorization_profiles:list[dict[str,Any]]=Field(default_factory=list,max_length=10); notes:str|None=None

    @model_validator(mode='before')
    @classmethod
    def defaults_for_profile(cls, values):
        if not isinstance(values,dict): return values
        values=dict(values); profile=values.get('profile','standard')
        presets={
            'baseline': {'max_pages':100,'max_depth':4,'max_endpoints':500,'request_delay_ms':300,'max_concurrency':2,'enable_browser':False,'enable_api_introspection':False,'enable_safe_parameter_probes':False,'passive_only':True},
            'standard': {'max_pages':300,'max_depth':8,'max_endpoints':2000,'request_delay_ms':150,'max_concurrency':4,'enable_browser':True,'enable_api_introspection':True,'enable_safe_parameter_probes':True,'passive_only':False},
            'comprehensive': {'max_pages':1500,'max_depth':12,'max_endpoints':7000,'request_delay_ms':200,'max_concurrency':4,'enable_browser':True,'enable_api_introspection':True,'enable_safe_parameter_probes':True,'passive_only':False},
        }
        for key,value in presets.get(profile,presets['standard']).items(): values.setdefault(key,value)
        return values

    @field_validator('request_headers')
    @classmethod
    def validate_request_headers(cls, value):
        blocked={'host','content-length','transfer-encoding','connection','proxy-authorization','proxy-connection','upgrade'}
        if len(value)>50: raise ValueError('At most 50 custom request headers are allowed')
        for key,val in value.items():
            if not key or len(key)>100 or key.lower() in blocked: raise ValueError(f'Forbidden or invalid custom header: {key}')
            if '\r' in key or '\n' in key or '\r' in str(val) or '\n' in str(val): raise ValueError('Newlines are forbidden in custom headers')
            if len(str(val))>8192: raise ValueError('Header values must be at most 8192 characters')
        return value

    @field_validator('authorization_profiles')
    @classmethod
    def validate_profiles(cls, value):
        if len(value)>10: raise ValueError('At most 10 authorization profiles are allowed')
        for item in value:
            if not isinstance(item,dict): raise ValueError('Authorization profile must be an object')
            name=str(item.get('name','profile'))
            if len(name)>100: raise ValueError('Authorization profile name is too long')
            headers=item.get('headers') or {}
            if not isinstance(headers,dict) or len(headers)>50: raise ValueError('Authorization profile headers are invalid')
            for key,val in headers.items():
                if not str(key) or len(str(key))>100 or str(key).lower() in {'host','content-length','transfer-encoding','connection','proxy-authorization','proxy-connection','upgrade'}: raise ValueError(f'Forbidden or invalid authorization profile header: {key}')
                if len(str(val))>8192: raise ValueError('Authorization profile header values must be at most 8192 characters')
                if '\r' in str(key)+str(val) or '\n' in str(key)+str(val): raise ValueError('Newlines are forbidden in authorization profile headers')
        return value
class ScanSummary(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:str;target_url:str;status:ScanStatus;created_at:datetime;started_at:datetime|None=None;finished_at:datetime|None=None;error:str|None=None
class ScanDetail(ScanSummary): config:dict[str,Any];pages_count:int=0;assets_count:int=0;findings_count:int=0;events_count:int=0
class FindingOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:str;rule_id:str;category:str;title:str;severity:Severity;confidence:float;risk_score:float;status:FindingStatus;endpoint:str;description:str;impact:str;remediation:str;references:list[Any];evidence_summary:str
class EventOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:str;phase:str;message:str;progress:float;created_at:datetime
class AssetOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id:str;url:str;kind:str;method:str;status_code:int|None;content_type:str|None;source:str;authenticated:bool;metadata_json:dict[str,Any]
