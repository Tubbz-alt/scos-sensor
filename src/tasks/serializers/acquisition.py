from rest_framework import serializers
from rest_framework.reverse import reverse

from sensor import V1
from tasks.models import Acquisition


class AcquisitionHyperlinkedRelatedField(serializers.HyperlinkedRelatedField):
    # django-rest-framework.org/api-guide/relations/#custom-hyperlinked-fields
    def get_url(self, obj, view_name, request, format):
        kws = {
            "schedule_entry_id": obj.task_result.schedule_entry.id,
            "task_id": obj.task_result.task_id,
        }
        kws.update(V1)
        url = reverse(view_name, kwargs=kws, request=request, format=format)
        return url


class AcquisitionSerializer(serializers.ModelSerializer):
    archive = AcquisitionHyperlinkedRelatedField(
        view_name="task-result-archive",
        read_only=True,
        help_text="The url to download a SigMF archive of this acquisition",
        source="*",  # pass whole object
    )
    metadata = serializers.DictField(help_text="The SigMF metadata for the acquisition")

    class Meta:
        model = Acquisition
        fields = ("recording_id", "archive", "metadata")
        extra_kwargs = {
            "schedule_entry": {"view_name": "schedule-detail", "lookup_field": "id"}
        }
