package aws

import (
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/medialive"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceAwsMedialiveInputSecurityGroup() *schema.Resource {
	return &schema.Resource{
		Create: func(d *schema.ResourceData, meta interface{}) error { return nil },
		Read:   func(d *schema.ResourceData, meta interface{}) error { return nil },
		Update: func(d *schema.ResourceData, meta interface{}) error { return nil },
		Delete: func(d *schema.ResourceData, meta interface{}) error { return nil },

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(10 * time.Minute),
		},

		SchemaVersion: 1,

		Schema: map[string]*schema.Schema{
			"whitelist_rules": {
				Type:       schema.TypeSet,
				Optional:   true,
				Computed:   true,
				ConfigMode: schema.SchemaConfigModeAttr,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cidr_block": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validateCIDRNetworkAddress,
						},
					},
				},
				Set: func(v interface{}) int { return 0 },
			},

			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"owner_id": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"tags": tagsSchema(),

			"revoke_rules_on_delete": {
				Type:     schema.TypeBool,
				Default:  false,
				Optional: true,
			},
		},
	}
}

func resourceAwsMedialiveInputSecurityGroupCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).medialiveconn

	securityGroupOpts := &medialive.CreateInputSecurityGroupInput{}

	if v, ok := d.GetOk("whitelist_rules"); ok {
		securityGroupOpts.SetWhitelistRules(v.([]*medialive.InputWhitelistRuleCidr))
	}

	var err error
	log.Printf("[DEBUG] Security Group create configuration: %#v", securityGroupOpts)
	createResp, err := conn.CreateInputSecurityGroup(securityGroupOpts)
	if err != nil {
		return fmt.Errorf("Error creating Security Group: %s", err)
	}

	d.SetId(*createResp.SecurityGroup.Id)

	log.Printf("[INFO] Security Group ID: %s", d.Id())

	// Wait for the security group to truly exist
	resp, err := waitForMedialiveSgToExist(conn, d.Id(), d.Timeout(schema.TimeoutCreate))
	if err != nil {
		return fmt.Errorf(
			"Error waiting for Security Group (%s) to become available: %s",
			d.Id(), err)
	}
	log.Printf("%v", resp)

	/*if err := setTags(conn, d); err != nil {
		return err
	}*/

	return nil
}

// SGStateRefreshFunc returns a resource.StateRefreshFunc that is used to watch
// a security group.
func MedialiveSGStateRefreshFunc(conn *medialive.MediaLive, id string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		req := &medialive.DescribeInputSecurityGroupInput{
			InputSecurityGroupId: aws.String(id),
		}
		resp, err := conn.DescribeInputSecurityGroup(req)
		if err != nil {
			if ec2err, ok := err.(awserr.Error); ok {
				if ec2err.Code() == "InvalidSecurityGroupID.NotFound" ||
					ec2err.Code() == "InvalidGroup.NotFound" {
					resp = nil
					err = nil
				}
			}

			if err != nil {
				log.Printf("Error on SGStateRefresh: %s", err)
				return nil, "", err
			}
		}

		if resp == nil {
			return nil, "", nil
		}

		group := resp
		return group, "exists", nil
	}
}

func waitForMedialiveSgToExist(conn *medialive.MediaLive, id string, timeout time.Duration) (interface{}, error) {
	log.Printf("[DEBUG] Waiting for Security Group (%s) to exist", id)
	stateConf := &resource.StateChangeConf{
		Pending: []string{""},
		Target:  []string{"exists"},
		Refresh: MedialiveSGStateRefreshFunc(conn, id),
		Timeout: timeout,
	}

	return stateConf.WaitForState()
}

func resourceAwsSecurityGroupRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	var sgRaw interface{}
	var err error
	if d.IsNewResource() {
		sgRaw, err = waitForSgToExist(conn, d.Id(), d.Timeout(schema.TimeoutRead))
	} else {
		sgRaw, _, err = SGStateRefreshFunc(conn, d.Id())()
	}

	if err != nil {
		return err
	}

	if sgRaw == nil {
		log.Printf("[WARN] Security group (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	sg := sgRaw.(*ec2.SecurityGroup)

	remoteIngressRules := resourceAwsSecurityGroupIPPermGather(d.Id(), sg.IpPermissions, sg.OwnerId)
	remoteEgressRules := resourceAwsSecurityGroupIPPermGather(d.Id(), sg.IpPermissionsEgress, sg.OwnerId)

	localIngressRules := d.Get("ingress").(*schema.Set).List()
	localEgressRules := d.Get("egress").(*schema.Set).List()

	// Loop through the local state of rules, doing a match against the remote
	// ruleSet we built above.
	ingressRules := matchRules("ingress", localIngressRules, remoteIngressRules)
	egressRules := matchRules("egress", localEgressRules, remoteEgressRules)

	sgArn := arn.ARN{
		AccountID: aws.StringValue(sg.OwnerId),
		Partition: meta.(*AWSClient).partition,
		Region:    meta.(*AWSClient).region,
		Resource:  fmt.Sprintf("security-group/%s", aws.StringValue(sg.GroupId)),
		Service:   ec2.ServiceName,
	}

	d.Set("arn", sgArn.String())
	d.Set("description", sg.Description)
	d.Set("name", sg.GroupName)
	d.Set("vpc_id", sg.VpcId)
	d.Set("owner_id", sg.OwnerId)

	if err := d.Set("ingress", ingressRules); err != nil {
		log.Printf("[WARN] Error setting Ingress rule set for (%s): %s", d.Id(), err)
	}

	if err := d.Set("egress", egressRules); err != nil {
		log.Printf("[WARN] Error setting Egress rule set for (%s): %s", d.Id(), err)
	}

	d.Set("tags", tagsToMap(sg.Tags))
	return nil
}

func resourceAwsSecurityGroupUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	var sgRaw interface{}
	var err error
	if d.IsNewResource() {
		sgRaw, err = waitForSgToExist(conn, d.Id(), d.Timeout(schema.TimeoutRead))
	} else {
		sgRaw, _, err = SGStateRefreshFunc(conn, d.Id())()
	}

	if err != nil {
		return err
	}
	if sgRaw == nil {
		log.Printf("[WARN] Security group (%s) not found, removing from state", d.Id())
		d.SetId("")
		return nil
	}

	group := sgRaw.(*ec2.SecurityGroup)

	err = resourceAwsSecurityGroupUpdateRules(d, "ingress", meta, group)
	if err != nil {
		return err
	}

	if d.Get("vpc_id") != nil {
		err = resourceAwsSecurityGroupUpdateRules(d, "egress", meta, group)
		if err != nil {
			return err
		}
	}

	if !d.IsNewResource() {
		if err := setTags(conn, d); err != nil {
			return err
		}
		d.SetPartial("tags")
	}

	return resourceAwsSecurityGroupRead(d, meta)
}

func resourceAwsSecurityGroupDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).ec2conn

	log.Printf("[DEBUG] Security Group destroy: %v", d.Id())

	if err := deleteLingeringLambdaENIs(conn, "group-id", d.Id(), d.Timeout(schema.TimeoutDelete)); err != nil {
		return fmt.Errorf("error deleting Lambda ENIs using Security Group (%s): %s", d.Id(), err)
	}

	// conditionally revoke rules first before attempting to delete the group
	if v := d.Get("revoke_rules_on_delete").(bool); v {
		if err := forceRevokeSecurityGroupRules(conn, d); err != nil {
			return err
		}
	}
	input := &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(d.Id()),
	}
	err := resource.Retry(d.Timeout(schema.TimeoutDelete), func() *resource.RetryError {
		_, err := conn.DeleteSecurityGroup(input)
		if err != nil {
			if isAWSErr(err, "InvalidGroup.NotFound", "") {
				return nil
			}
			if isAWSErr(err, "DependencyViolation", "") {
				// If it is a dependency violation, we want to retry
				return resource.RetryableError(err)
			}
			return resource.NonRetryableError(err)
		}
		return nil
	})
	if isResourceTimeoutError(err) {
		_, err = conn.DeleteSecurityGroup(input)
		if isAWSErr(err, "InvalidGroup.NotFound", "") {
			return nil
		}
	}
	if err != nil {
		return fmt.Errorf("Error deleting security group: %s", err)
	}
	return nil
}
